// Copyright (c) 2022 The Parca Authors
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
		if err := e.Extract(ctx, dst, src); err != nil {
			level.Warn(e.logger).Log(
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
func (e *Extractor) Extract(ctx context.Context, dst io.WriteSeeker, src string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	elfFile, err := open(src)
	if err != nil {
		return fmt.Errorf("failed to open given field: %w", err)
	}
	defer elfFile.Close()

	w, err := elfwriter.New(dst, &elfFile.FileHeader)
	if err != nil {
		return fmt.Errorf("failed to initialize writer: %w", err)
	}

	for _, p := range elfFile.Progs {
		if p.Type == elf.PT_NOTE {
			w.Progs = append(w.Progs, p)
		}
	}
	for _, s := range elfFile.Sections {
		if s.Name == ".text" {
			// .text section is the main executable code, so we only need to use the header of the section.
			// Header of this section is required to be able to symbolize Go binaries.
			w.SectionHeaders = append(w.SectionHeaders, s.SectionHeader)
		}
		if isDwarf(s) || isSymbolTable(s) || isGoSymbolTable(s) || s.Type == elf.SHT_NOTE {
			w.Sections = append(w.Sections, s)
		}
	}

	if err := w.Write(); err != nil {
		return fmt.Errorf("failed to write ELF file: %w", err)
	}

	level.Debug(e.logger).Log("msg", "debug information successfully extracted")
	return nil
}

func open(filePath string) (*elf.File, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening %s: %w", filePath, err)
	}
	defer f.Close()

	// Read the first 4 bytes of the file.
	var header [4]byte
	if _, err = io.ReadFull(f, header[:]); err != nil {
		return nil, fmt.Errorf("error reading magic number from %s: %w", filePath, err)
	}

	// Match against supported file types.
	if elfMagic := string(header[:]); elfMagic == elf.ELFMAG {
		f, err := elf.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("error reading ELF file %s: %w", filePath, err)
		}
		return f, nil
	}

	return nil, fmt.Errorf("unrecognized object file format: %s", filePath)
}

var isDwarf = func(s *elf.Section) bool {
	return strings.HasPrefix(s.Name, ".debug_") ||
		strings.HasPrefix(s.Name, ".zdebug_") ||
		strings.HasPrefix(s.Name, "__debug_") // macos
}

var isSymbolTable = func(s *elf.Section) bool {
	return s.Name == ".symtab" ||
		s.Name == ".dynsymtab" ||
		s.Name == ".strtab" ||
		s.Type == elf.SHT_SYMTAB ||
		s.Type == elf.SHT_DYNSYM ||
		s.Type == elf.SHT_STRTAB
}

var isGoSymbolTable = func(s *elf.Section) bool {
	return s.Name == ".gosymtab" || s.Name == ".gopclntab" || s.Name == ".go.buildinfo"
}
