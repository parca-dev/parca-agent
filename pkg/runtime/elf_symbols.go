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
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/xyproto/ainur"
)

func HasSymbols(ef *elf.File, matches [][]byte) (bool, error) {
	var (
		hasSymbols bool
		err        error
	)

	if hasSymbols, err = IsSymbolNameInSymbols(ef, matches); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return hasSymbols, fmt.Errorf("search symbols: %w", err)
	}

	if !hasSymbols {
		if hasSymbols, err = IsSymbolNameInDynamicSymbols(ef, matches); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return hasSymbols, fmt.Errorf("search dynamic symbols: %w", err)
		}
	}

	return hasSymbols, nil
}

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

func isSymbolNameInSection(ef *elf.File, t elf.SectionType, matches [][]byte) (bool, error) {
	symtabSection := ef.SectionByType(t)
	if symtabSection == nil {
		return false, elf.ErrNoSymbols
	}

	strtabReader, err := stringTableReader(ef, symtabSection.Link)
	if err != nil {
		return false, fmt.Errorf("cannot load string table section: %w", err)
	}

	sr, err := ainur.NewStreamReader(strtabReader, 8192)
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

// FindSymbol finds symbol by name in the given elf file.
func FindSymbol(ef *elf.File, symbol string) (*elf.Symbol, error) {
	rgx := regexp.MustCompile(fmt.Sprintf("\\b%s\\b", symbol)) // Exact match.

	sym, err := getSymbol(ef, elf.SHT_SYMTAB, rgx)
	// If there are no symbols, try dynamic symbols.
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("error getting ELF symbols: %w", err)
	}
	if sym != nil {
		return sym, nil
	}

	sym, err = getSymbol(ef, elf.SHT_DYNSYM, rgx)
	if err != nil {
		return nil, fmt.Errorf("error reading ELF dynamic symbols: %w", err)
	}
	if sym != nil {
		return sym, nil
	}

	return nil, fmt.Errorf("symbol %q not found", symbol)
}

func getSymbol(ef *elf.File, typ elf.SectionType, rgx *regexp.Regexp) (*elf.Symbol, error) {
	switch ef.Class {
	case elf.ELFCLASS64:
		return getSymbol64(ef, typ, rgx)

	case elf.ELFCLASS32:
		return getSymbol32(ef, typ, rgx)

	case elf.ELFCLASSNONE:
		fallthrough

	default:
		return nil, fmt.Errorf("unknown ELF class: %v", ef.Class)
	}
}

func getSymbol32(ef *elf.File, typ elf.SectionType, rgx *regexp.Regexp) (*elf.Symbol, error) {
	symtabSection := ef.SectionByType(typ)
	if symtabSection == nil {
		return nil, elf.ErrNoSymbols
	}

	strdataReader, err := stringTableReader(ef, symtabSection.Link)
	if err != nil {
		return nil, fmt.Errorf("cannot load string table section: %w", err)
	}

	match := rgx.FindReaderIndex(bufio.NewReader(strdataReader))
	if match == nil {
		return nil, fmt.Errorf("symbol not found, matcher %q", rgx.String())
	}

	data, err := symtabSection.Data()
	if err != nil {
		return nil, fmt.Errorf("cannot load symbol section: %w", err)
	}

	symtab := bytes.NewReader(data)
	if symtab.Len()%elf.Sym64Size != 0 {
		return nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}

	// The first entry is all zeros.
	var skip [elf.Sym32Size]byte
	_, err = symtab.Read(skip[:])
	if err != nil {
		return nil, fmt.Errorf("cannot read first entry: %w", err)
	}

	var sym elf.Sym32
	for symtab.Len() > 0 {
		if err := binary.Read(symtab, ef.ByteOrder, &sym); err != nil {
			return nil, fmt.Errorf("cannot read symbol: %w", err)
		}

		if sym.Name != uint32(match[0]) {
			continue
		}

		str, err := readStringFromReaderSeeker(strdataReader, int(sym.Name))
		if err != nil {
			return nil, fmt.Errorf("cannot read symbol name: %w", err)
		}

		return &elf.Symbol{
			Name:    str,
			Info:    sym.Info,
			Other:   sym.Other,
			Section: elf.SectionIndex(sym.Shndx),
			Value:   uint64(sym.Value),
			Size:    uint64(sym.Size),
		}, nil
	}

	return nil, fmt.Errorf("symbol not found, matcher %q", rgx.String())
}

func getSymbol64(ef *elf.File, typ elf.SectionType, rgx *regexp.Regexp) (*elf.Symbol, error) {
	symtabSection := ef.SectionByType(typ)
	if symtabSection == nil {
		return nil, elf.ErrNoSymbols
	}

	strdataReader, err := stringTableReader(ef, symtabSection.Link)
	if err != nil {
		return nil, fmt.Errorf("cannot load string table section: %w", err)
	}

	match := rgx.FindReaderIndex(bufio.NewReader(strdataReader))
	if match == nil {
		return nil, fmt.Errorf("symbol not found, matcher %q", rgx.String())
	}

	data, err := symtabSection.Data()
	if err != nil {
		return nil, fmt.Errorf("cannot load symbol section: %w", err)
	}

	symtab := bytes.NewReader(data)
	if symtab.Len()%elf.Sym64Size != 0 {
		return nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}

	// The first entry is all zeros.
	var skip [elf.Sym64Size]byte
	_, err = symtab.Read(skip[:])
	if err != nil {
		return nil, fmt.Errorf("cannot read first entry: %w", err)
	}

	var sym elf.Sym64
	for symtab.Len() > 0 {
		if err := binary.Read(symtab, ef.ByteOrder, &sym); err != nil {
			return nil, fmt.Errorf("cannot read symbol: %w", err)
		}

		if sym.Name != uint32(match[0]) {
			continue
		}

		str, err := readStringFromReaderSeeker(strdataReader, match[0])
		if err != nil {
			return nil, fmt.Errorf("cannot read symbol name: %w", err)
		}

		return &elf.Symbol{
			Name:    str,
			Info:    sym.Info,
			Other:   sym.Other,
			Section: elf.SectionIndex(sym.Shndx),
			Value:   sym.Value,
			Size:    sym.Size,
		}, nil
	}

	return nil, fmt.Errorf("symbol not found, matcher %q", rgx.String())
}

// readStringFromReaderSeeker extracts a zero-terminated string from an ELF string table io.Reader.
func readStringFromReaderSeeker(rs io.ReadSeeker, start int) (string, error) {
	_, err := rs.Seek(int64(start), io.SeekStart)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	for {
		var b [1]byte
		if _, err := rs.Read(b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			break
		}
		buf.Write(b[:])
	}

	return buf.String(), nil
}

// stringTable reads and returns the string table given by the
// specified link value.
func stringTableReader(ef *elf.File, link uint32) (io.ReadSeeker, error) {
	if link <= 0 || link >= uint32(len(ef.Sections)) {
		return nil, errors.New("section has invalid string table link")
	}
	return ef.Sections[link].Open(), nil
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
