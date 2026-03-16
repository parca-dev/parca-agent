// Copyright 2022-2024 The Parca Authors
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

package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchContainerID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "containerd prefixed ID",
			input: "containerd://a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e",
			want:  "a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e",
		},
		{
			name:  "docker prefixed ID",
			input: "docker://55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
			want:  "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
		},
		{
			name:  "cri-o prefixed ID",
			input: "cri-o://deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			want:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		{
			name:  "bare container ID from CRI API",
			input: "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
			want:  "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "short hex string",
			input:   "a4fdf2f3",
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			input:   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: true,
		},
		{
			name:    "65 hex chars rejected",
			input:   "a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e0",
			wantErr: true,
		},
		{
			name:    "cgroup path not matched",
			input:   "12:memory:/kubepods/burstable/pod123/a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e",
			wantErr: true,
		},
		{
			name:    "hex with trailing chars rejected",
			input:   "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03axyz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := matchContainerID(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
