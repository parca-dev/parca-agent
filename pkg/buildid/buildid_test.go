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

package buildid

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildID(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "go binary",
			args: args{
				path: "./testdata/readelf-sections",
			},
			want: "38485a695f33313366465a4977783952383553352f7061675079616d5137476a525276786b447243682f564636356c4b554450384b684e71766d5133314a2f49765f39585a33486b576a684f57306661525158",
		},
		{
			name: "rust binary",
			args: args{
				path: "./testdata/rust",
			},
			want: "ea8a38018312ad155fa70e471d4e0039ff9971c6",
		},
		{
			name: "rust binary build with bazel",
			args: args{
				path: "./testdata/bazel-rust",
			},
			want: "983bd888c60ead8e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildID(tt.args.path)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_fastGNUBuildID(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "rust binary",
			args: args{
				path: "./testdata/rust",
			},
			want: "ea8a38018312ad155fa70e471d4e0039ff9971c6",
		},
		{
			name: "rust binary build with bazel",
			args: args{
				path: "./testdata/bazel-rust",
			},
			want: "983bd888c60ead8e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fastGNUBuildID(tt.args.path)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, hex.EncodeToString(got))
		})
	}
}

func Test_elfBuildID(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "go binary",
			args: args{
				path: "./testdata/readelf-sections",
			},
			want: "bd1ca7c3af25af95", // fallbacks to hash of .text
		},
		{
			name: "rust binary",
			args: args{
				path: "./testdata/rust",
			},
			want: "ea8a38018312ad155fa70e471d4e0039ff9971c6",
		},
		{
			name: "rust binary build with bazel",
			args: args{
				path: "./testdata/bazel-rust",
			},
			want: "983bd888c60ead8e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := elfBuildID(tt.args.path)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_fastGoBuildID(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "go binary",
			args: args{
				path: "./testdata/readelf-sections",
			},
			want: "8HZi_313fFZIwx9R85S5/pagPyamQ7GjRRvxkDrCh/VF65lKUDP8KhNqvmQ31J/Iv_9XZ3HkWjhOW0faRQX",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fastGoBuildID(tt.args.path)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, string(got))
		})
	}
}
