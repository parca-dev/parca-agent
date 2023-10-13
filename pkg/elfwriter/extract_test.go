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
	"testing"

	"github.com/parca-dev/parca/pkg/symbol/elfutils"
	"github.com/rzajac/flexbuf"
	"github.com/stretchr/testify/require"
)

func TestExtractor_Extract(t *testing.T) {
	type args struct {
		src string
	}
	tests := []struct {
		name                   string
		args                   args
		wantErr                bool
		expectedProgramHeaders []elf.ProgHeader
	}{
		{
			name: "valid extracted debuginfo",
			args: args{
				src: "../debuginfo/testdata/readelf-sections",
			},
			expectedProgramHeaders: []elf.ProgHeader{
				{
					Type:   elf.PT_NOTE,
					Flags:  elf.PF_R,
					Off:    3996,
					Vaddr:  4198300,
					Paddr:  4198300,
					Filesz: 100,
					Memsz:  100,
					Align:  4,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := flexbuf.New()
			f, err := os.Open(tt.args.src)
			t.Cleanup(func() {
				f.Close()
			})
			require.NoError(t, err)

			err = extract(buf, f)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Should be valid ELF file.
			buf.SeekStart()
			elfFile, err := elf.NewFile(buf)
			require.NoError(t, err)

			// Should not contain any data for text section, but .text exists.
			textSec := elfFile.Section(".text")
			textData, err := textSec.Data()
			require.NoError(t, err)

			require.Equal(t, 0, len(textData))

			// Should have expectedProgramHeaders
			require.Equal(t, len(tt.expectedProgramHeaders), len(elfFile.Progs))
			for i, prog := range elfFile.Progs {
				expectedProgramHeader := tt.expectedProgramHeaders[i]
				require.Equal(t, expectedProgramHeader, prog.ProgHeader)
			}
		})
	}
}

func TestExtractingCompressedSections(t *testing.T) {
	testfiles := []string{
		"./testdata/basic-cpp-dwarf",
		"./testdata/basic-cpp-dwarf-compressed",
		"./testdata/basic-cpp-dwarf-compressed-corrupted",
	}

	visit := func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !f.IsDir() {
			testfiles = append(testfiles, path)
		}
		return nil
	}
	if err := filepath.Walk("../../testdata/vendored", visit); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk("../../testdata/out", visit); err != nil {
		t.Fatal(err)
	}

	for _, testfile := range testfiles {
		ef, err := elf.Open(testfile)
		require.NoError(t, err)

		if !elfutils.HasDWARF(ef) {
			ef.Close()
			continue
		}
		ef.Close()

		t.Run(fmt.Sprintf("testfile=%s", testfile), func(t *testing.T) {
			buf := flexbuf.New()
			f, err := os.Open(testfile)
			require.NoError(t, err)
			t.Cleanup(func() {
				f.Close()
			})

			err = extract(buf, f)
			require.NoError(t, err)

			// Should be valid ELF file.
			buf.SeekStart()
			ef, err := elf.NewFile(buf)
			require.NoError(t, err)

			// Should have valid DWARF sections.
			_, err = ef.DWARF()
			require.NoError(t, err)

			ogElf, err := elf.NewFile(f)
			require.NoError(t, err)

			for _, ogSec := range ogElf.Sections {
				if isDWARF(ogSec) {
					sec := ef.Section(ogSec.Name)
					if sec == nil {
						t.Logf("could not find, section: %s\n", ogSec.Name)
						continue
					}

					ogData, err := ogSec.Data()
					require.NoError(t, err)

					data, err := sec.Data()
					require.NoError(t, err)

					require.Equalf(t, len(ogData), len(data), "section: %s, type: %s, flags: %s", sec.Name, sec.Type, sec.Flags)
					require.Equalf(t, ogData, data, "section: %s, type: %s, flags: %s", sec.Name, sec.Type, sec.Flags)
				}
			}
		})
	}
}
