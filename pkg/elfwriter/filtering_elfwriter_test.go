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

package elfwriter

import (
	"debug/elf"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilteringWriter_PreserveLinks(t *testing.T) {
	file, err := os.Open("testdata/libc.so.6")
	require.NoError(t, err)
	t.Cleanup(func() {
		defer file.Close()
	})

	output, err := ioutil.TempFile("", "test-output.*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Remove(output.Name())
	})

	w, err := NewFromSource(output, file)
	require.NoError(t, err)

	w.FilterSections(func(s *elf.Section) bool {
		return s.Name == ".rela.dyn" // refers to .dynsym and .dynsym refers to .dynstr
	})
	w.FilterHeaderOnlySections(func(s *elf.Section) bool {
		return s.Name == ".text"
	})
	require.NoError(t, w.Flush())

	outElf, err := elf.Open(output.Name())
	require.NoError(t, err)

	dynsym := outElf.Section(".dynsym")
	require.NotNil(t, dynsym)

	data, err := dynsym.Data()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	dynstr := outElf.Section(".dynstr")
	require.NotNil(t, dynstr)

	data, err = dynstr.Data()
	require.NoError(t, err)
	require.Greater(t, len(data), 0)
}
