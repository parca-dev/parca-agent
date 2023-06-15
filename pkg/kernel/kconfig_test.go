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

package kernel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBpfConfig(t *testing.T) {
	testcases := []struct {
		name      string
		path      string
		want      string
		wantErr   bool
		isEnabled bool
	}{
		{
			name:      "Config file with correct config",
			path:      "testdata/procconfig.gz",
			wantErr:   false,
			isEnabled: true,
		},
		{
			name:      "Config file with correct config from alternative option",
			path:      "testdata/config-alternative-found",
			wantErr:   false,
			isEnabled: true,
		},
		{
			name:      "Config file with missing option",
			path:      "testdata/config-5.17.15-76051715-generic",
			want:      "kernel config required for ebpf not found, Config Option:CONFIG_BPF_JIT",
			wantErr:   true,
			isEnabled: false,
		},
		{
			name:      "Config file with missing option, no alternatives",
			path:      "testdata/config-alternative-fail",
			want:      "kernel config required for ebpf not found, Config Option:CONFIG_BPF_JIT_ALWAYS_ON; alternatives checked:CONFIG_ARCH_WANT_DEFAULT_BPF_JIT",
			wantErr:   true,
			isEnabled: false,
		},
		{
			name:      "Config file with disabled option",
			path:      "testdata/config",
			want:      "kernel config required for ebpf is disabled, Config Option:CONFIG_BPF_EVENTS",
			wantErr:   true,
			isEnabled: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			// check for the file read failures
			config, err := getConfig(tt.path)
			require.NoError(t, err)
			require.NotEmpty(t, config)

			isBPFEnabled, err := checkBPFOptions(tt.path)

			if tt.wantErr {
				require.Error(t, err, tt.want)
			} else {
				require.NoError(t, err, nil)
			}
			require.Equal(t, tt.isEnabled, isBPFEnabled)
		})
	}
}
