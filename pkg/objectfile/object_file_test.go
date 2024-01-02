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
	objFilePool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), "", 10, 0)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	t.Run("Malformed ELF", func(t *testing.T) {
		// Test that opening a malformed ELF ObjectFile will report an error containing
		// the word "ELF".
		_, err := objFilePool.Open(filepath.Join("./testdata", "exe_linux_64", "malformed_elf"))
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
		elfOpen = func(_ string) (*elf.File, error) {
			return &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_EXEC}}, errors.New("elf.Open failed")
		}
		t.Cleanup(func() {
			elfNewFile = elf.NewFile
			elfOpen = elf.Open
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
		if !strings.Contains(err.Error(), "error opening") {
			t.Errorf("Open: got %v, want error 'elf.Open failed'", err)
		}
	})
}
