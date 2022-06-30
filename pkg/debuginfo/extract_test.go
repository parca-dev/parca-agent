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
	"testing"

	"github.com/go-kit/log"
	"github.com/rzajac/flexbuf"
	"github.com/stretchr/testify/require"
)

func TestExtractor_Extract(t *testing.T) {
	type args struct {
		src string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid extracted debuginfo",
			args: args{
				src: "../../dist/parca-agent",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Extractor{
				logger: log.NewNopLogger(),
			}
			buf := flexbuf.New()
			err := e.Extract(context.TODO(), buf, tt.args.src)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Should be valid ELF file.
			buf.SeekStart()
			elfFile, err := elf.NewFile(buf)
			require.NoError(t, err)

			// Should not contain any data for text section.
			textSec := elfFile.Section(".text")
			textData, err := textSec.Data()
			require.NoError(t, err)

			require.Equal(t, 0, len(textData))
		})
	}
}
