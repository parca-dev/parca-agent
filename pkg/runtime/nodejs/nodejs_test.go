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

package nodejs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_scanVersionBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    string
		expectedErr bool
	}{
		{
			name:        "empty",
			input:       []byte{},
			expectedErr: true,
		},
		{
			name:        "unmatched",
			input:       []byte("asdasd"),
			expectedErr: true,
		},
		{
			name:     "v1.2.3",
			input:    []byte("asdasd v1.2.3 asdasd"),
			expected: "v1.2.3",
		},
		{
			name:        "only major",
			input:       []byte("asdasd v1 asdasd"),
			expectedErr: true,
		},
		{
			name:        "only major and minor",
			input:       []byte("asdasd v1.2 asdasd"),
			expectedErr: true,
		},
		{
			name:     "Pre-release",
			input:    []byte("asdasd v1.2.3-pre (asdasd)"),
			expected: "v1.2.3-pre",
		},
		{
			name:     "Release candidate",
			input:    []byte("asdasd v1.2.3-rc.1 (asdasd)"),
			expected: "v1.2.3-rc.1",
		},
		{
			name:     "Build metadata",
			input:    []byte("asdasd v1.2.3+build.1 (asdasd)"),
			expected: "v1.2.3+build.1",
		},
		{
			name:     "Pre-release and build metadata",
			input:    []byte("asdasd v1.2.3-pre+build.1 (asdasd)"),
			expected: "v1.2.3-pre+build.1",
		},
		{
			name:     "With nodejs/ prefix",
			input:    []byte(`asdasd nodejs/v1.2.3-pre+build.1 (asdasd)`),
			expected: "v1.2.3-pre+build.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := scanVersionBytes(tt.input)
			if tt.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expected, version)
		})
	}
}

func Test_isNodeJSLib(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "libnode",
			input: " /usr/bin/../lib/libnode.so.120",
			want:  true,
		},
		{
			name:  "libnode with version",
			input: " /usr/bin/../lib/libnode.so.120",
			want:  true,
		},
		{
			name:  "Dynamic lib with suffix",
			input: "/usr/lib/x86_64-linux-gnu/libnode.so.64.0.0d",
			want:  true,
		},
		{
			name:  "Static lib",
			input: "/usr/lib/x86_64-linux-gnu/libnode.a",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isNodeJSLib(tt.input))
		})
	}
}
