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
	"testing"

	"github.com/stretchr/testify/require"
)

func isDebug(s *elf.Section) bool {
	return isDWARF(s) || isSymbolTable(s) || isGoSymbolTable(s)
}

func TestFilteringWriter_Write(t *testing.T) {
	input, err := os.Open("testdata/agent-binary")
	require.NoError(t, err)
	t.Cleanup(func() {
		input.Close()
	})
	type fields struct {
		progPredicates          []func(*elf.Prog) bool
		sectionPredicates       []func(*elf.Section) bool
		sectionHeaderPredicates []func(*elf.Section) bool
	}
	tests := []struct {
		name                     string
		fields                   fields
		err                      error
		expectedNumberOfProgs    int
		expectedNumberOfSections int
		isSymbolizable           bool
		hasDWARF                 bool
	}{
		{
			name: "only keep file header",
			fields: fields{
				progPredicates: []func(*elf.Prog) bool{
					func(p *elf.Prog) bool { return false },
				},
				sectionPredicates: []func(*elf.Section) bool{
					func(section *elf.Section) bool { return false },
				},
			},
		},
		{
			name: "only keep program header",
			fields: fields{
				progPredicates: []func(*elf.Prog) bool{
					func(p *elf.Prog) bool { return true },
				},
				sectionPredicates: []func(*elf.Section) bool{
					func(section *elf.Section) bool { return false },
				},
			},
			expectedNumberOfProgs: 7,
		},
		{
			name: "keep all sections and segments",
			fields: fields{
				progPredicates: []func(*elf.Prog) bool{
					func(p *elf.Prog) bool { return true },
				},
				sectionPredicates: []func(*elf.Section) bool{
					func(section *elf.Section) bool { return true },
				},
			},
			expectedNumberOfProgs:    7,
			expectedNumberOfSections: 23,
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
		{
			name: "keep all sections except DWARF information",
			fields: fields{
				sectionPredicates: []func(s *elf.Section) bool{
					func(s *elf.Section) bool {
						return !isDWARF(s)
					},
				},
			},
			expectedNumberOfProgs:    7,
			expectedNumberOfSections: 16,
			isSymbolizable:           true,
		},
		{
			name: "keep only debug information",
			fields: fields{
				sectionPredicates: []func(s *elf.Section) bool{
					isDebug,
				},
			},
			expectedNumberOfProgs:    7,
			expectedNumberOfSections: 14, // + 2 shstrtab, SHT_NULL
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
		{
			name: "keep only debug information with text",
			fields: fields{
				sectionPredicates: []func(s *elf.Section) bool{
					isDebug,
				},
				sectionHeaderPredicates: []func(s *elf.Section) bool{
					func(s *elf.Section) bool {
						return s.Name == textSectionName
					},
				},
			},
			expectedNumberOfProgs:    7,
			expectedNumberOfSections: 15, // + 3 shstrtab, SHT_NULL, .text
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

			w, err := NewFilteringWriter(output, input)
			require.NoError(t, err)

			w.FilterPrograms(tt.fields.progPredicates...)
			w.FilterSections(tt.fields.sectionPredicates...)
			w.FilterHeaderOnlySections(tt.fields.sectionHeaderPredicates...)

			err = w.Flush()
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}

			outElf, err := elf.Open(output.Name())
			require.NoError(t, err)

			require.Equal(t, tt.expectedNumberOfProgs, len(outElf.Progs))
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

			if len(w.sectionHeaders) > 0 {
				for _, s := range w.sectionHeaders {
					require.NotNil(t, outElf.Section(s.Name))
				}
			}
		})
	}
}

func TestFilteringWriter_PreserveLinks(t *testing.T) {
	file, err := os.Open("testdata/libc.so.6")
	require.NoError(t, err)
	t.Cleanup(func() {
		defer file.Close()
	})

	output, err := os.CreateTemp("", "test-output.*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Remove(output.Name())
	})

	w, err := NewFilteringWriter(output, file)
	require.NoError(t, err)

	w.FilterSections(func(s *elf.Section) bool {
		return s.Name == ".rela.dyn" // refers to .dynsym and .dynsym refers to .dynstr
	})
	w.FilterHeaderOnlySections(func(s *elf.Section) bool {
		return s.Name == ".text"
	})
	require.NoError(t, w.Flush())

	outElf, err := elf.Open(output.Name())
	require.NoError(t, err)

	dynsym := outElf.Section(".dynsym")
	require.NotNil(t, dynsym)

	data, err := dynsym.Data()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	dynstr := outElf.Section(".dynstr")
	require.NotNil(t, dynstr)

	data, err = dynstr.Data()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)
}
