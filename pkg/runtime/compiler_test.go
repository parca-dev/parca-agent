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

package runtime

import (
	"testing"
)

func Test_version(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "GCC 7.2.0",
			want:  "7.2.0",
		},
		{
			input: "Clang 8.2.1",
			want:  "8.2.1",
		},
		{
			input: "Go 1.16.5",
			want:  "1.16.5",
		},
		{
			input: "Rust (GCC 9.3.0)",
			want:  "",
		},
		{
			input: "Rust 1.27.0-nightly",
			want:  "1.27.0-nightly",
		},
		{
			input: "DMD",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := version(tt.input); got != "" && got != tt.want {
				t.Errorf("version() = %v, want %v", got, tt.want)
			}
		})
	}
}
