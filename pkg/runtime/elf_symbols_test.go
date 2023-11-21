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

package runtime

import (
	"debug/elf"
	"testing"
)

func Benchmark_isSymbolNameInSection(b *testing.B) {
	f, err := elf.Open("testdata/libpython3.11.so.1.0")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := isSymbolNameInSection(f, elf.SHT_DYNSYM, [][]byte{[]byte("_PyRuntime")})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Test_isSymbolNameInSection(t *testing.T) {
	type args struct {
		path    string
		t       elf.SectionType
		matches [][]byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "_PyRuntime dynamic",
			args: args{
				path:    "testdata/libpython3.11.so.1.0",
				t:       elf.SHT_DYNSYM,
				matches: [][]byte{[]byte("_PyRuntime")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "_PyRuntime static",
			args: args{
				path:    "testdata/libpython3.11.so.1.0",
				t:       elf.SHT_SYMTAB,
				matches: [][]byte{[]byte("_PyRuntime")},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := elf.Open(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				f.Close()
			})
			got, err := isSymbolNameInSection(f, tt.args.t, tt.args.matches)
			if (err != nil) != tt.wantErr {
				t.Errorf("isSymbolNameInSection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isSymbolNameInSection() = %v, want %v", got, tt.want)
			}
		})
	}
}
