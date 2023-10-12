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
	"debug/elf"
	"os"
	"strings"
	"testing"

	"github.com/parca-dev/parca/pkg/symbol/elfutils"
	"github.com/stretchr/testify/require"
)

const textSectionName = ".text"

var isNote = func(s *elf.Section) bool {
	return strings.HasPrefix(s.Name, ".note")
}

func isSymbolizableGoObjFile(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	return elfutils.HasGoPclntab(f), nil
}

func hasSymbols(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	return elfutils.HasSymtab(f) || elfutils.HasDynsym(f), nil
}

func hasPlt(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	return f.Section(".rela.plt") != nil && f.Section(".plt") != nil, nil
}

func TestWriter_Write(t *testing.T) {
	inElf, err := elf.Open("testdata/agent-binary")
	require.NoError(t, err)
	t.Cleanup(func() {
		inElf.Close()
	})

	var secExceptDebug []*elf.Section
	for _, s := range inElf.Sections {
		if !isDWARF(s) {
			secExceptDebug = append(secExceptDebug, s)
		}
	}

	var secDebug []*elf.Section
	for _, s := range inElf.Sections {
		if isDWARF(s) || isSymbolTable(s) || isGoSymbolTable(s) || isNote(s) {
			secDebug = append(secDebug, s)
		}
	}

	type fields struct {
		FileHeader     *elf.FileHeader
		Progs          []*elf.Prog
		Sections       []*elf.Section
		SectionHeaders []elf.SectionHeader
	}
	tests := []struct {
		name                     string
		fields                   fields
		err                      error
		expectedNumberOfSections int
		isSymbolizable           bool
		hasDWARF                 bool
	}{
		{
			name: "only keep file header",
			fields: fields{
				FileHeader: &inElf.FileHeader,
			},
		},
		{
			name: "only keep program header",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Progs:      inElf.Progs,
			},
		},
		{
			name: "keep all sections and segments",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Progs:      inElf.Progs,
				Sections:   inElf.Sections,
			},
			expectedNumberOfSections: len(inElf.Sections),
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
		{
			name: "keep all sections except debug information",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Sections:   secExceptDebug,
			},
			expectedNumberOfSections: len(secExceptDebug),
			isSymbolizable:           true,
		},
		{
			name: "keep only debug information",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Sections:   secDebug,
			},
			expectedNumberOfSections: len(secDebug) + 1, // SHT_NULL
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
		{
			name: "keep only debug information with text",
			fields: fields{
				FileHeader:     &inElf.FileHeader,
				Sections:       secDebug,
				SectionHeaders: []elf.SectionHeader{inElf.Section(textSectionName).SectionHeader},
			},
			expectedNumberOfSections: len(secDebug) + 2, // SHT_NULL, .text
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := os.CreateTemp("", "test-output.*")
			require.NoError(t, err)
			t.Cleanup(func() {
				os.Remove(output.Name())
			})

			w, err := newWriter(output, &inElf.FileHeader, newSectionWriterWithoutRawSource(&inElf.FileHeader))
			require.NoError(t, err)

			w.progs = append(w.progs, tt.fields.Progs...)
			w.sections = append(w.sections, tt.fields.Sections...)
			w.sectionHeaders = append(w.sectionHeaders, tt.fields.SectionHeaders...)

			err = w.Flush()
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}

			outElf, err := elf.Open(output.Name())
			require.NoError(t, err)

			require.Equal(t, len(tt.fields.Progs), len(outElf.Progs))
			require.Equal(t, tt.expectedNumberOfSections, len(outElf.Sections))

			if tt.isSymbolizable {
				res, err := isSymbolizableGoObjFile(output.Name())
				require.NoError(t, err)
				require.True(t, res)

				res, err = hasSymbols(output.Name())
				require.NoError(t, err)
				require.True(t, res)
			}

			if tt.hasDWARF {
				data, err := outElf.DWARF()
				require.NoError(t, err)
				require.NotNil(t, data)
			}

			if len(tt.fields.SectionHeaders) > 0 {
				for _, s := range tt.fields.SectionHeaders {
					require.NotNil(t, outElf.Section(s.Name))
				}
			}
		})
	}
}

func TestWriter_WriteCompressedHeaders(t *testing.T) {
	file, err := os.Open("testdata/libc_compressed.debug")
	require.NoError(t, err)
	t.Cleanup(func() {
		file.Close()
	})

	input, err := elf.NewFile(file)
	require.NoError(t, err)
	t.Cleanup(func() {
		defer input.Close()
	})

	output, err := os.CreateTemp("", "test-output.*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Remove(output.Name())
	})

	w, err := NewFilteringWriter(output, file)
	require.NoError(t, err)

	w.FilterSections(func(s *elf.Section) bool {
		return isDWARF(s) || isSymbolTable(s) || isGoSymbolTable(s) || s.Type == elf.SHT_NOTE
	})
	w.FilterHeaderOnlySections(func(s *elf.Section) bool {
		return s.Name == textSectionName
	})
	require.NoError(t, w.Flush())

	outElf, err := elf.Open(output.Name())
	require.NoError(t, err)

	compressedSec := outElf.Section(".debug_aranges")
	require.NotNil(t, compressedSec)

	dOut, err := compressedSec.Data()
	require.NoError(t, err)
	require.NotNil(t, dOut)

	compressedSec = input.Section(".debug_aranges")
	dIn, err := compressedSec.Data()
	require.NoError(t, err)
	require.NotNil(t, dIn)

	require.Equal(t, dIn, dOut)
}

func TestWriter_HasLinks(t *testing.T) {
	inElf, err := elf.Open("testdata/libc.so.6")
	require.NoError(t, err)
	t.Cleanup(func() {
		inElf.Close()
	})

	type fields struct {
		FileHeader     *elf.FileHeader
		Progs          []*elf.Prog
		Sections       []*elf.Section
		SectionHeaders []elf.SectionHeader
	}
	tests := []struct {
		name                     string
		fields                   fields
		err                      error
		expectedNumberOfSections int
		isSymbolizable           bool
		havePlt                  bool
	}{
		{
			name: "only keep file header",
			fields: fields{
				FileHeader: &inElf.FileHeader,
			},
		},
		{
			name: "only keep program header",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Progs:      inElf.Progs,
			},
		},
		{
			name: "keep all sections and segments",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Progs:      inElf.Progs,
				Sections:   inElf.Sections,
			},
			expectedNumberOfSections: len(inElf.Sections),
			isSymbolizable:           true,
			havePlt:                  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := os.CreateTemp("", "test-output-links.*")
			require.NoError(t, err)

			t.Cleanup(func() {
				os.Remove(output.Name())
			})

			w, err := newWriter(output, &inElf.FileHeader, newSectionWriterWithoutRawSource(&inElf.FileHeader))
			require.NoError(t, err)

			w.progs = append(w.progs, tt.fields.Progs...)
			w.sections = append(w.sections, tt.fields.Sections...)
			w.sectionHeaders = append(w.sectionHeaders, tt.fields.SectionHeaders...)

			err = w.Flush()
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}

			outElf, err := elf.Open(output.Name())
			require.NoError(t, err)

			require.Equal(t, len(tt.fields.Progs), len(outElf.Progs))
			require.Equal(t, tt.expectedNumberOfSections, len(outElf.Sections))

			if tt.isSymbolizable {
				res, err := hasSymbols(output.Name())
				require.NoError(t, err)
				require.True(t, res)
			}

			if tt.havePlt {
				res, err := hasPlt(output.Name())
				require.NoError(t, err)
				require.True(t, res)
			}

			if len(tt.fields.SectionHeaders) > 0 {
				for _, s := range tt.fields.SectionHeaders {
					require.NotNil(t, outElf.Section(s.Name))
				}
			}
		})
	}
}
