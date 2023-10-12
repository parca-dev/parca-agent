// Copyright 2022-2023 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package elfwriter

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"go.opentelemetry.io/otel/trace"
)

// Extractor extracts debug information from a binary.
type Extractor struct {
	logger log.Logger
	tracer trace.Tracer
}

// NewExtractor creates a new Extractor.
func NewExtractor(logger log.Logger, tracer trace.Tracer) *Extractor {
	return &Extractor{
		logger: log.With(logger, "component", "extractor"),
		tracer: tracer,
	}
}

// ExtractAll extracts debug information from the given executables.
// It consumes a map of file sources to extract and a destination io.Writer.
func (e *Extractor) ExtractAll(ctx context.Context, srcDsts map[string]io.WriteSeeker) error {
	var result error
	for src, dst := range srcDsts {
		f, err := os.Open(src)
		if err != nil {
			level.Debug(e.logger).Log("msg", "failed to open file", "file", src, "err", err)
			result = errors.Join(result, err)
			continue
		}
		defer f.Close()

		if err := e.Extract(ctx, dst, f); err != nil {
			level.Debug(e.logger).Log(
				"msg", "failed to extract debug information", "file", src, "err", err,
			)
			result = errors.Join(result, err)
		}
	}
	return result
}

// Extract extracts debug information from the given executable.
// Cleaning up the temporary directory and the interim file is the caller's responsibility.
func (e *Extractor) Extract(ctx context.Context, dst io.WriteSeeker, src io.ReaderAt) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	_, span := e.tracer.Start(ctx, "DebuginfoExtractor.Extract")
	defer span.End()

	return extract(dst, src)
}

func extract(dst io.WriteSeeker, src io.ReaderAt) error {
	w, err := NewFilteringWriter(dst, src)
	if err != nil {
		return fmt.Errorf("failed to initialize writer: %w", err)
	}
	w.FilterPrograms(func(p *elf.Prog) bool {
		return p.Type == elf.PT_NOTE
	})
	w.FilterSections(
		isDWARF,
		isSymbolTable,
		isGoSymbolTable,
		isPltSymbolTable, // TODO(kakkoyun): objdump don't keep these section. We should look into this.
		func(s *elf.Section) bool {
			return s.Type == elf.SHT_NOTE
		},
	)
	w.FilterHeaderOnlySections(func(s *elf.Section) bool {
		// .text section is the main executable code, so we only need to use the header of the section.
		// Header of this section is required to be able to symbolize Go binaries.
		return s.Name == ".text"
	})

	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to write ELF file: %w", err)
	}
	return nil
}
