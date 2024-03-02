// Copyright 2023-2024 The Parca Authors
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
	"bytes"
	"debug/elf"
	"io"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

const testdata = "../../../testdata"

//nolint:unparam
func testBinaryPath(p string) string {
	return path.Join(testdata, "vendored", runtime.GOARCH, p)
}

func Test_scanVersionBytes(t *testing.T) {
	ef, err := elf.Open(testBinaryPath("node20.8"))
	require.NoError(t, err)
	t.Cleanup(func() { ef.Close() })

	sec := ef.Section(".rodata")
	require.NotNil(t, sec)

	roSec := ef.Section(".rodata")
	require.NotNil(t, roSec)

	tests := []struct {
		name        string
		input       io.ReadSeeker
		expected    string
		expectedErr bool
	}{
		{
			name:        "empty",
			input:       bytes.NewReader([]byte{}),
			expectedErr: true,
		},
		{
			name:        "unmatched",
			input:       bytes.NewReader([]byte("asdasd")),
			expectedErr: true,
		},
		{
			name:     "v1.2.3",
			input:    bytes.NewReader([]byte("asdasd v1.2.3 asdasd")),
			expected: "v1.2.3",
		},
		{
			name:        "only major",
			input:       bytes.NewReader([]byte("asdasd v1 asdasd")),
			expectedErr: true,
		},
		{
			name:        "only major and minor",
			input:       bytes.NewReader([]byte("asdasd v1.2 asdasd")),
			expectedErr: true,
		},
		{
			name:     "Pre-release",
			input:    bytes.NewReader([]byte("asdasd v1.2.3-pre (asdasd)")),
			expected: "v1.2.3-pre",
		},
		{
			name:     "Release candidate",
			input:    bytes.NewReader([]byte("asdasd v1.2.3-rc.1 (asdasd)")),
			expected: "v1.2.3-rc.1",
		},
		{
			name:     "Build metadata",
			input:    bytes.NewReader([]byte("asdasd v1.2.3+build.1 (asdasd)")),
			expected: "v1.2.3+build.1",
		},
		{
			name:     "Pre-release and build metadata",
			input:    bytes.NewReader([]byte("asdasd v1.2.3-pre+build.1 (asdasd)")),
			expected: "v1.2.3-pre+build.1",
		},
		{
			name:     "With nodejs/ prefix",
			input:    bytes.NewReader([]byte(`asdasd nodejs/v1.2.3-pre+build.1 (asdasd)`)),
			expected: "v1.2.3-pre+build.1",
		},
		{
			name:     "With real data, .data",
			input:    sec.Open(),
			expected: "v20.8.1",
		},
		{
			name:     "With real data, .rodata",
			input:    roSec.Open(),
			expected: "v20.8.1",
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

func Benchmark_scanVersionBytes(b *testing.B) {
	ef, err := elf.Open(testBinaryPath("node20.8"))
	require.NoError(b, err)

	sec := ef.Section(".rodata")
	require.NotNil(b, sec)

	roSec := ef.Section(".rodata")
	require.NotNil(b, roSec)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanVersionBytes(sec.Open())
		require.NoError(b, err)

		_, err = scanVersionBytes(roSec.Open())
		require.NoError(b, err)
	}
}
