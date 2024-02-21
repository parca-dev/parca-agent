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

package erlang

import (
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

const testdata = "../../../testdata"

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

func TestAll(t *testing.T) {
	file := testBinaryPath("beam.smp")

	isBeam, err := IsBEAM(file)
	require.NoError(t, err)
	require.True(t, isBeam)

	f, err := os.Open(file)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })

	version, err := versionFromFile(f)
	require.NoError(t, err)
	require.Equal(t, "25.3.2.6", version)
}
