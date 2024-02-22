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

package runtime

import (
	"debug/elf"
	"fmt"
	"path"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const testdata = "../../testdata"

// TODO(kakkoyun): Change upstream to use GOARCH.
func arch() string {
	ar := runtime.GOARCH
	switch ar {
	case "amd64":
		return "x86"
	default:
		return ar
	}
}

//nolint:unparam
func testBinaryPath(p string) string {
	return path.Join(testdata, "vendored", arch(), p)
}

func Benchmark_isSymbolNameInSection(b *testing.B) {
	f, err := elf.Open(testBinaryPath("libpython3.11.so.1.0"))
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
	libpython := testBinaryPath("libpython3.11.so.1.0")

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
				path:    libpython,
				t:       elf.SHT_DYNSYM,
				matches: [][]byte{[]byte("_PyRuntime")},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "_PyRuntime static",
			args: args{
				path:    libpython,
				t:       elf.SHT_SYMTAB,
				matches: [][]byte{[]byte("_PyRuntime")},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ef, err := elf.Open(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ef.Close()
			})

			got, err := isSymbolNameInSection(ef, tt.args.t, tt.args.matches)
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

func TestFindSymbol(t *testing.T) {
	libpython := testBinaryPath("libpython3.11.so.1.0")

	examples := map[string]*elf.Symbol{
		"amd64/_PyRuntime": {
			Name:    "_PyRuntime",
			Info:    17,
			Other:   0,
			Section: 25,
			Value:   0x0000000000557d20,
			Size:    166688,
		},
		"arm64/_PyRuntime": {
			Name:    "_PyRuntime",
			Info:    17,
			Other:   0,
			Section: 23,
			Value:   0x00000000005542f8,
			Size:    166704,
		},
		"amd64/_PyRuntimeState_Fini": {
			Name:    "_PyRuntimeState_Fini",
			Info:    18,
			Other:   0,
			Section: 13,
			Value:   0x000000000029a7a0,
			Size:    148,
		},
		"arm64/_PyRuntimeState_Fini": {
			Name:    "_PyRuntimeState_Fini",
			Info:    18,
			Other:   0,
			Section: 11,
			Value:   0x0000000000293ba0,
			Size:    156,
		},
	}

	type args struct {
		path   string
		symbol string
	}
	tests := []struct {
		name    string
		args    args
		want    *elf.Symbol
		wantErr bool
	}{
		{
			name: "find _PyRuntime",
			args: args{
				path:   libpython,
				symbol: "_PyRuntime",
			},
			want:    examples[fmt.Sprintf("%s/%s", runtime.GOARCH, "_PyRuntime")],
			wantErr: false,
		},
		{
			name: "find _PyRuntimeState_Fini",
			args: args{
				path:   libpython,
				symbol: "_PyRuntimeState_Fini",
			},
			want:    examples[fmt.Sprintf("%s/%s", runtime.GOARCH, "_PyRuntimeState_Fini")],
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ef, err := elf.Open(tt.args.path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ef.Close()
			})
			got, err := FindSymbol(ef, tt.args.symbol)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindSymbol(%s) error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(elf.Symbol{})); diff != "" {
				t.Errorf("FindSymbol(%s) on %s mismatch (-want +got):\n%s", tt.name, runtime.GOARCH, diff)
			}
		})
	}
}

func BenchmarkFindSymbol(b *testing.B) {
	f, err := elf.Open(testBinaryPath("libpython3.11.so.1.0"))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := FindSymbol(f, "_PyRuntime")
		if err != nil {
			b.Fatal(err)
		}
	}
}
