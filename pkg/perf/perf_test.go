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

package perf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

func mustReadFile(file string) []byte {
	b, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPerfMapParse(t *testing.T) {
	fs := &realfs{}
	res, err := ReadMap(fs, "testdata/nodejs-perf-map")
	require.NoError(t, err)
	require.Len(t, res.addrs, 28)
	// Check for 4edd3cca B0 LazyCompile:~Timeout internal/timers.js:55
	require.Equal(t, res.addrs[12], MapAddr{0x4edd4f12, 0x4edd4f47, "LazyCompile:~remove internal/linkedlist.js:15"})

	// Look-up a symbol.
	sym, err := res.Lookup(0x4edd4f12 + 4)
	require.NoError(t, err)
	require.Equal(t, sym, "LazyCompile:~remove internal/linkedlist.js:15")

	_, err = res.Lookup(0xFFFFFFFF)
	require.ErrorIs(t, err, ErrNoSymbolFound)
}

func TestPerfMapParseErlangPerfMap(t *testing.T) {
	fs := &realfs{}
	_, err := ReadMap(fs, "testdata/erlang-perf-map")
	require.NoError(t, err)
}

func BenchmarkPerfMapParse(b *testing.B) {
	fs := &realfs{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ReadMap(fs, "testdata/nodejs-perf-map")
		require.NoError(b, err)
	}
}

func BenchmarkPerfMapParseBig(b *testing.B) {
	fs := &realfs{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ReadMap(fs, "testdata/erlang-perf-map")
		require.NoError(b, err)
	}
}

func TestFindNSPid(t *testing.T) {
	fs := testutil.NewFakeFS(map[string][]byte{
		"/proc/25803/status": mustReadFile("testdata/proc-status"),
	})

	pid, err := FindNSPIDs(fs, 25803)
	require.NoError(t, err)

	require.Equal(t, []int{25803, 1}, pid)
}

func TestExtractPidsFromLine(t *testing.T) {
	pid, err := extractPIDsFromLine("NSpid:\t25803\t1")
	require.NoError(t, err)

	require.Equal(t, []int{25803, 1}, pid)
}
