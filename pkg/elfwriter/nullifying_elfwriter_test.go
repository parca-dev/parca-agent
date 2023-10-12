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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNullifyingWriter_Write(t *testing.T) {
	input, err := os.Open("testdata/basic-cpp-dwarf")
	require.NoError(t, err)
	t.Cleanup(func() {
		input.Close()
	})
	type fields struct {
		progPredicates    []func(*elf.Prog) bool
		sectionPredicates []func(*elf.Section) bool
	}
	tests := []struct {
		name                             string
		fields                           fields
		err                              error
		expectedNumberOfProgs            int
		expectedNumberOfSections         int
		expectedNumberOfSectionsWithBits int
		isSymbolizable                   bool
		hasDWARF                         bool
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
			expectedNumberOfProgs:            0,
			expectedNumberOfSections:         34,
			expectedNumberOfSectionsWithBits: 1, // .shstrtab
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
			expectedNumberOfProgs:            13,
			expectedNumberOfSections:         34,
			expectedNumberOfSectionsWithBits: 1, // .shstrtab
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
			expectedNumberOfProgs:            13,
			expectedNumberOfSections:         34,
			expectedNumberOfSectionsWithBits: 32, // .bss, SHT_NULL
			isSymbolizable:                   true,
			hasDWARF:                         true,
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
			expectedNumberOfProgs:            13,
			expectedNumberOfSections:         34,
			expectedNumberOfSectionsWithBits: 26,
			isSymbolizable:                   true,
		},
		{
			name: "keep only debug information",
			fields: fields{
				sectionPredicates: []func(s *elf.Section) bool{
					isDebug,
				},
			},
			expectedNumberOfProgs:            13,
			expectedNumberOfSections:         34,
			expectedNumberOfSectionsWithBits: 11,
			isSymbolizable:                   true,
			hasDWARF:                         true,
		},
		{
			name: "keep only debug information with text",
			fields: fields{
				sectionPredicates: []func(s *elf.Section) bool{
					isDebug,
				},
			},
			expectedNumberOfProgs:            13,
			expectedNumberOfSections:         34,
			expectedNumberOfSectionsWithBits: 11,
			isSymbolizable:                   true,
			hasDWARF:                         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := os.CreateTemp("", "test-output.*")
			require.NoError(t, err)
			t.Cleanup(func() {
				os.Remove(output.Name())
			})

			w, err := NewNullifyingWriter(output, input)
			require.NoError(t, err)

			w.FilterPrograms(tt.fields.progPredicates...)
			w.KeepSections(tt.fields.sectionPredicates...)

			err = w.Flush()
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}

			outElf, err := elf.Open(output.Name())
			require.NoError(t, err)

			// TODO(kakkoyun): Remove!
			out, err := os.Create(fmt.Sprintf("./testdata/interim/nullified-%s-%s", filepath.Base(t.Name()), filepath.Base(input.Name())))
			require.NoError(t, err)

			in, err := os.ReadFile(output.Name())
			require.NoError(t, err)

			err = os.WriteFile(out.Name(), in, 0o644)
			require.NoError(t, err)

			og, err := elf.NewFile(input)
			require.NoError(t, err)

			ogNames := []string{}
			for _, s := range og.Sections {
				ogNames = append(ogNames, s.Name)
			}
			names := []string{}
			for _, s := range outElf.Sections {
				names = append(names, s.Name)
			}
			require.Equal(t, ogNames, names)

			require.Equal(t, tt.expectedNumberOfProgs, len(outElf.Progs))
			require.Equal(t, tt.expectedNumberOfSections, len(outElf.Sections))

			sectionWithBits := 0
			for _, s := range outElf.Sections {
				d, err := s.Data()
				if err != nil && strings.Contains(err.Error(), "unexpected read from SHT_NOBITS section") {
					continue
				}
				if len(d) > 0 {
					sectionWithBits += 1
				}
			}
			require.Equal(t, tt.expectedNumberOfSectionsWithBits, sectionWithBits)

			if tt.isSymbolizable {
				res, err := hasSymbols(output.Name())
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

func TestNullifyingWriter_PreserveLinks(t *testing.T) {
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

	w, err := NewNullifyingWriter(output, file)
	require.NoError(t, err)

	w.KeepSections(func(s *elf.Section) bool {
		return s.Name == ".rela.dyn" // refers to .dynsym and .dynsym refers to .dynstr
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
