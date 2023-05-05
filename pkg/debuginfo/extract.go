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

package debuginfo

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-multierror"

	"github.com/parca-dev/parca-agent/pkg/elfwriter"
)

// Extractor extracts debug information from a binary.
type Extractor struct {
	logger log.Logger
}

// NewExtractor creates a new Extractor.
func NewExtractor(logger log.Logger) *Extractor {
	return &Extractor{
		logger: log.With(logger, "component", "extractor"),
	}
}

// ExtractAll extracts debug information from the given executables.
// It consumes a map of file sources to extract and a destination io.Writer.
func (e *Extractor) ExtractAll(ctx context.Context, srcDsts map[string]io.WriteSeeker) error {
	var result *multierror.Error
	for src, dst := range srcDsts {
		f, err := os.Open(src)
		if err != nil {
			level.Debug(e.logger).Log("msg", "failed to open file", "file", src, "err", err)
			result = multierror.Append(result, err)
			continue
		}
		defer f.Close()

		if err := Extract(ctx, dst, f); err != nil {
			level.Debug(e.logger).Log(
				"msg", "failed to extract debug information", "file", src, "err", err,
			)
			result = multierror.Append(result, err)
		}
	}

	if result != nil && len(result.Errors) > 0 {
		return result.ErrorOrNil()
	}

	return nil
}

// Extract extracts debug information from the given executable.
// Cleaning up the temporary directory and the interim file is the caller's responsibility.
func Extract(ctx context.Context, dst io.WriteSeeker, f *os.File) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	w, err := elfwriter.NewFromSource(dst, f)
	if err != nil {
		return fmt.Errorf("failed to initialize writer: %w", err)
	}
	w.FilterPrograms(func(p *elf.Prog) bool {
		return p.Type == elf.PT_NOTE
	})
	w.FilterSections(
		isDwarf,
		isSymbolTable,
		isGoSymbolTable,
		isPltSymbolTable,
		func(s *elf.Section) bool {
			return s.Type == elf.SHT_NOTE
		})
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

var isDwarf = func(s *elf.Section) bool {
	return strings.HasPrefix(s.Name, ".debug_") ||
		strings.HasPrefix(s.Name, ".zdebug_") ||
		strings.HasPrefix(s.Name, "__debug_") // macos
}

var isSymbolTable = func(s *elf.Section) bool {
	return s.Name == ".symtab" ||
		s.Name == ".dynsym" ||
		s.Name == ".strtab" ||
		s.Name == ".dynstr" ||
		s.Type == elf.SHT_SYMTAB ||
		s.Type == elf.SHT_DYNSYM ||
		s.Type == elf.SHT_STRTAB
}

var isGoSymbolTable = func(s *elf.Section) bool {
	return s.Name == ".gosymtab" || s.Name == ".gopclntab" || s.Name == ".go.buildinfo"
}

var isPltSymbolTable = func(s *elf.Section) bool {
	return s.Name == ".rela.plt" || s.Name == ".plt"
}
