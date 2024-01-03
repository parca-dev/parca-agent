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

package jit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/jit"
)

const testdataDir = "../../test/testdata/jitdump"

func getCases() []struct {
	runtime string
	err     error
} {
	return []struct {
		runtime string
		err     error
	}{
		{
			runtime: "dotnet",
			err:     nil,
		},
		{
			runtime: "erlang",
			err:     nil,
		},
		{
			runtime: "julia",
			err:     nil,
		},
		{
			runtime: "libperf-jvmti",
			// JVM updates its JITted code all the time,
			// it is close to impossible to catch a full dump.
			err: io.ErrUnexpectedEOF,
		},
		{
			runtime: "nodejs",
			err:     nil,
		},
		{
			runtime: "php",
			err:     nil,
		},
		{
			runtime: "wasmtime",
			err:     nil,
		},
	}
}

func TestLoadJITDump(t *testing.T) {
	t.Parallel()

	logger := log.NewNopLogger()

	for _, tt := range getCases() {
		tc := tt
		t.Run(tc.runtime, func(t *testing.T) {
			t.Parallel()

			fixture := fmt.Sprintf("%s/%s.dump", testdataDir, tc.runtime)
			snapshot := fmt.Sprintf("%s/%s.json", testdataDir, tc.runtime)

			// Read fixture
			f, err := os.Open(fixture)
			require.NoError(t, err)
			defer f.Close()

			// Load JITDUMP from fixture
			dump := &jit.JITDump{}
			err = jit.LoadJITDump(logger, f, dump)
			require.ErrorIs(t, err, tc.err)

			// Encode JITDUMP to JSON
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			err = enc.Encode(dump)
			require.NoError(t, err)
			actual := buf.Bytes()

			// Read JSON snapshot
			expected, err := os.ReadFile(snapshot)
			if err != nil {
				if !os.IsNotExist(err) {
					require.NoError(t, err)
				}
				os.WriteFile(snapshot, actual, 0o600)
				expected = []byte{}
			}

			// Register cleanup function if snapshot needs update
			t.Cleanup(func() {
				if t.Failed() && os.Getenv("SNAPSHOT") == "overwrite" {
					os.WriteFile(snapshot, actual, 0o600)
				}
			})

			// Compare actual and expected dumps
			require.Equal(t, string(expected), string(actual), "To update the snapshot, run `SNAPSHOT=overwrite go test ./pkg/jit`")
		})
	}
}

func BenchmarkLoadJITDump(b *testing.B) {
	b.ReportAllocs()

	logger := log.NewNopLogger()

	for _, bb := range getCases() {
		b.Run(bb.runtime, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fixture := fmt.Sprintf("%s/%s.dump", testdataDir, bb.runtime)

				// Read fixture
				f, err := os.Open(fixture)
				require.NoError(b, err)
				defer f.Close()

				// Load JITDUMP from fixture
				err = jit.LoadJITDump(logger, f, &jit.JITDump{})
				require.ErrorIs(b, err, bb.err)
			}
		})
	}
}
