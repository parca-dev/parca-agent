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

package perf

import (
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/symtab"
)

func createTestFile(tb testing.TB) string {
	tb.Helper()
	f, err := os.CreateTemp(tb.TempDir(), "")
	require.NoError(tb, err)
	require.NoError(tb, f.Close())
	return f.Name()
}

func TestPerfMapParse(t *testing.T) {
	filename := createTestFile(t)
	defer os.Remove(filename)

	f, _, err := optimizeAndOpenPerfMap(
		log.NewNopLogger(),
		"testdata/nodejs-perf-map",
		filename,
		0,
	)
	require.NoError(t, err)
	h := f.Header()
	require.Equal(t, 28, int(h.AddressesCount))

	// Look-up a symbol.
	sym, err := f.Symbolize(0x4edd4f12 + 4)
	require.NoError(t, err)
	require.Equal(t, "LazyCompile:~remove internal/linkedlist.js:15", sym)
}

func TestPerfMapCorruptLine(t *testing.T) {
	filename := createTestFile(t)
	defer os.Remove(filename)

	w, err := symtab.NewWriter(filename, 0)
	require.NoError(t, err)

	_, err = parsePerfMapLine([]byte(" Script:~ evalmachine.<anonymous>:1\r\n"), w)
	require.Error(t, err)
}

func TestPerfMapRegression(t *testing.T) {
	filename := createTestFile(t)
	defer os.Remove(filename)

	_, _, err := optimizeAndOpenPerfMap(
		log.NewNopLogger(),
		"testdata/nodejs-perf-map-regression",
		filename,
		0,
	)
	require.NoError(t, err)
}

func TestPerfMapParseErlangPerfMap(t *testing.T) {
	filename := createTestFile(t)
	defer os.Remove(filename)

	_, _, err := optimizeAndOpenPerfMap(
		log.NewNopLogger(),
		"testdata/erlang-perf-map",
		filename,
		0,
	)
	require.NoError(t, err)
}

func BenchmarkPerfMapParse(b *testing.B) {
	logger := log.NewNopLogger()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filename := createTestFile(b)

		_, _, err := optimizeAndOpenPerfMap(
			logger,
			"testdata/nodejs-perf-map",
			filename,
			0,
		)
		require.NoError(b, err)
		require.NoError(b, os.Remove(filename))
	}
}

func BenchmarkPerfMapParseBig(b *testing.B) {
	logger := log.NewNopLogger()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filename := createTestFile(b)

		_, _, err := optimizeAndOpenPerfMap(
			logger,
			"testdata/erlang-perf-map",
			filename,
			0,
		)
		require.NoError(b, err)
		require.NoError(b, os.Remove(filename))
	}
}
