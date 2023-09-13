// Copyright 2023 The Parca Authors
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

package runtime

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"

	"github.com/xyproto/ainur"
)

// ForEachElfSymbolNameInSymbols iterates over the symbols in the symbol table
// of the given elf file. It calls the given function for each symbol name. The
// value is only valid for the iteration, it must not be saved unless copied.
func IsSymbolNameInSymbols(f *elf.File, matches [][]byte) (bool, error) {
	return isSymbolNameInSection(f, elf.SHT_SYMTAB, matches)
}

// ForEachElfSymbolNameInSymbols iterates over the symbols in the dynamic
// symbol table of the given elf file. It calls the given function for each
// symbol name. The value is only valid for the iteration, it must not be saved
// unless copied.
func IsSymbolNameInDynamicSymbols(f *elf.File, matches [][]byte) (bool, error) {
	return isSymbolNameInSection(f, elf.SHT_DYNSYM, matches)
}

func isSymbolNameInSection(f *elf.File, t elf.SectionType, matches [][]byte) (bool, error) {
	symtabSection := f.SectionByType(t)
	if symtabSection == nil {
		return false, elf.ErrNoSymbols
	}

	if symtabSection.Link <= 0 || symtabSection.Link >= uint32(len(f.Sections)) {
		return false, errors.New("section has invalid string table link")
	}

	s := f.Sections[symtabSection.Link].Open()

	sr, err := ainur.NewStreamReader(s, 8192)
	if err != nil {
		return false, fmt.Errorf("create stream reader: %w", err)
	}

	for {
		b, err := sr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false, fmt.Errorf("read next: %w", err)
		}

		// Look for the DMD marker
		for _, match := range matches {
			if bytes.Contains(b, match) {
				return true, nil
			}
		}
	}

	return false, nil
}

// TODO: Optimize!
// FindAddressOfSymbol finds the address of the given symbol in the given elf file
// by searching both the symbol table and the dynamic symbol table.
// Returns 0 if the symbol is not found.
func FindAddressOfSymbol(ef *elf.File, symbol string) (uint64, error) {
	symbols, err := ef.Symbols()
	if err != nil {
		return 0, fmt.Errorf("error reading ELF symbols: %w", err)
	}
	for _, s := range symbols {
		if s.Name == symbol {
			return s.Value, nil
		}
	}

	dynamicSymbols, err := ef.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("error reading ELF dynamic symbols: %w", err)
	}
	for _, s := range dynamicSymbols {
		if s.Name == symbol {
			return s.Value, nil
		}
	}

	return 0, nil
}

// FindSymbol finds symbol by name in the given elf file.
func FindSymbol(ef *elf.File, symbol string) (*elf.Symbol, error) {
	symbols, err := ef.Symbols()
	if err != nil {
		return nil, fmt.Errorf("error reading ELF symbols: %w", err)
	}
	for _, s := range symbols {
		if s.Name == symbol {
			return &s, nil
		}
	}

	dynamicSymbols, err := ef.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("error reading ELF dynamic symbols: %w", err)
	}
	for _, s := range dynamicSymbols {
		if s.Name == symbol {
			return &s, nil
		}
	}

	return nil, fmt.Errorf("symbol %q not found", symbol)
}

// ReadStringAtAddress reads a null-terminated string from the given address in
// the given elf file.
func ReadStringAtAddress(rs io.ReadSeeker, address, size uint64) (string, error) {
	_, err := rs.Seek(int64(address), io.SeekStart)
	if err != nil {
		return "", err
	}

	buf := make([]byte, size)
	_, err = rs.Read(buf)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}
