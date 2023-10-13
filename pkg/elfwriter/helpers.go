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
	"bytes"
	"compress/zlib"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
)

type zeroReader struct{}

func (*zeroReader) ReadAt(p []byte, off int64) (_ int, _ error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func copyCompressed(w io.Writer, r io.Reader) (uint64, uint64, error) {
	if r == nil {
		return 0, 0, errors.New("reader is nil")
	}

	pr, pw := io.Pipe()

	// write in writer end of pipe.
	var wErr error
	var read int64
	go func() {
		defer pw.Close()
		defer func() {
			if r := recover(); r != nil {
				debug.PrintStack()
				err, ok := r.(error)
				if ok {
					wErr = fmt.Errorf("panic occurred: %w", err)
				}
			}
		}()
		read, wErr = io.Copy(pw, r)
	}()

	// read from reader end of pipe.
	defer pr.Close()

	buf := bytes.NewBuffer(nil)
	zw := zlib.NewWriter(buf)
	if _, err := io.Copy(zw, pr); err != nil {
		zw.Close()
		return 0, 0, err
	}
	zw.Close()

	if wErr != nil {
		return 0, 0, wErr
	}

	written, err := w.Write(buf.Bytes())
	if err != nil {
		return 0, 0, err
	}

	return uint64(written), uint64(read), nil
}

func isDWARF(s *elf.Section) bool {
	return strings.HasPrefix(s.Name, ".debug_") ||
		strings.HasPrefix(s.Name, ".zdebug_") ||
		strings.HasPrefix(s.Name, "__debug_") // macos
}

func isSymbolTable(s *elf.Section) bool {
	return s.Name == ".symtab" ||
		s.Name == ".dynsym" ||
		s.Name == ".strtab" ||
		s.Name == ".dynstr" ||
		s.Type == elf.SHT_SYMTAB ||
		s.Type == elf.SHT_DYNSYM ||
		s.Type == elf.SHT_STRTAB
}

func isGoSymbolTable(s *elf.Section) bool {
	return s.Name == ".gosymtab" || s.Name == ".gopclntab" || s.Name == ".go.buildinfo"
}

func isPltSymbolTable(s *elf.Section) bool {
	return s.Name == ".rela.plt" || s.Name == ".plt"
}

func match[T *elf.Prog | *elf.Section | *elf.SectionHeader](elem T, predicates ...func(T) bool) bool {
	for _, pred := range predicates {
		if pred(elem) {
			return true
		}
	}
	return false
}
