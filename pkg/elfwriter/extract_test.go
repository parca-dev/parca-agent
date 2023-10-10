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
