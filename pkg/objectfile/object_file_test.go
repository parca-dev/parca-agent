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

// This package includes modified code from the github.com/google/pprof/internal/binutils

package objectfile

import (
	"debug/elf"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestOpenELF(t *testing.T) {
	objFilePool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 5)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	t.Run("Malformed ELF", func(t *testing.T) {
		// Test that opening a malformed ELF ObjectFile will report an error containing
		// the word "ELF".
		f, err := objFilePool.Open(filepath.Join("../../internal/pprof/binutils/testdata", "malformed_elf"))
		t.Cleanup(func() {
			f.Close()
		})
		if err == nil {
			t.Fatalf("Open: unexpected success")
		}
		if !strings.Contains(err.Error(), "error opening") {
			t.Errorf("Open: got %v, want error containing 'ELF'", err)
		}
	})

	t.Run("ELF Open Error", func(t *testing.T) {
		elfNewFile = func(_ io.ReaderAt) (*elf.File, error) {
			return &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_EXEC}}, errors.New("elf.NewFile failed")
		}
		t.Cleanup(func() {
			elfNewFile = elf.NewFile
		})

		f, err := os.CreateTemp("", "")
		require.NoError(t, err)
		t.Cleanup(func() {
			f.Close()
			os.Remove(f.Name())
		})

		_, err = objFilePool.NewFile(f)
		if err == nil {
			t.Fatalf("open: unexpected success")
		}
		if !strings.Contains(err.Error(), "failed check whether file is an ELF file") {
			t.Errorf("Open: got %v, want error 'elf.Open failed'", err)
		}
	})
}

func TestIsELF(t *testing.T) {
	tests := map[string]struct {
		filename string
		want     bool
	}{
		"ELF file": {
			filename: "testdata/fib",
			want:     true,
		},
		"text file": {
			filename: "object_file_test.go",
			want:     false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(tc.filename)
			require.NoError(t, err)
			defer f.Close()

			got, err := isELF(f)
			if err != nil {
				t.Fatal(err)
			}

			if got != tc.want {
				t.Errorf("expected %t got %t", tc.want, got)
			}
		})
	}
}

func TestHasTextSection(t *testing.T) {
	objFilePool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 5)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	testCases := []struct {
		name              string
		filepath          string
		textSectionExists bool
	}{
		{
			name:              "text section present",
			filepath:          "./testdata/readelf-sections",
			textSectionExists: true,
		},
		{
			name:              "text section absent",
			filepath:          "./testdata/elf-file-without-text-section",
			textSectionExists: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := objFilePool.Open(tc.filepath)
			t.Cleanup(func() {
				f.Close()
			})
			require.NoError(t, err)

			require.Equal(t, tc.textSectionExists, f.HasTextSection())
		})
	}
}

func BenchmarkIsELF(b *testing.B) {
	filename := "testdata/fib-nopie"
	f, err := os.Open(filename)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < b.N; i++ {
		if _, err := isELF(f); err != nil {
			b.Fatal(err)
		}
	}
}
