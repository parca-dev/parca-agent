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

func TestAggregatingWriter_Write(t *testing.T) {
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
				Sections:   cleanLinks(inElf.Sections),
			},
			expectedNumberOfSections: len(inElf.Sections),
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
		{
			name: "keep all sections except debug information",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Sections:   cleanLinks(secExceptDebug),
			},
			expectedNumberOfSections: len(secExceptDebug),
			isSymbolizable:           true,
		},
		{
			name: "keep only debug information",
			fields: fields{
				FileHeader: &inElf.FileHeader,
				Sections:   cleanLinks(secDebug),
			},
			expectedNumberOfSections: len(secDebug) + 1, // SHT_NULL
			isSymbolizable:           true,
			hasDWARF:                 true,
		},
		{
			name: "keep only debug information with text",
			fields: fields{
				FileHeader:     &inElf.FileHeader,
				Sections:       cleanLinks(secDebug),
				SectionHeaders: []elf.SectionHeader{inElf.Section(".text").SectionHeader},
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

			w, err := NewAggregatingWriter(output, &inElf.FileHeader)
			require.NoError(t, err)

			w.AddPrograms(tt.fields.Progs...)
			w.AddSections(tt.fields.Sections...)
			w.AddHeaderOnlySections(tt.fields.SectionHeaders...)

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

// Links should be relative to each other for AggregatingWriter,
// since we copy them for these set of tests we need to clean links.
func cleanLinks(sections []*elf.Section) []*elf.Section {
	for _, section := range sections {
		section.Link = 0
	}
	return sections
}
