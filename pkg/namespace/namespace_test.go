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

package namespace

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

func TestFindNSPid(t *testing.T) {
	fs := testutil.NewFakeFS(map[string][]byte{
		"/proc/25803/status": mustReadFile("testdata/proc-status"),
	})

	pid, err := FindPIDs(fs, 25803)
	require.NoError(t, err)

	require.Equal(t, []int{25803, 1}, pid)
}

func TestExtractPidsFromLine(t *testing.T) {
	pid, err := extractPIDsFromLine("NSpid:\t25803\t1")
	require.NoError(t, err)

	require.Equal(t, []int{25803, 1}, pid)
}

// TODO(kakkoyun): Add benchmarks for FindNSPIDs.
