// Copyright 2026 The Parca Authors
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

package gpumetrics

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCountNVIDIAGPUs(t *testing.T) {
	root := t.TempDir()
	require.Equal(t, 0, CountNVIDIAGPUs(root), "no driver loaded")

	for _, bus := range []string{"0000:01:00.0", "0000:02:00.0"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "driver/nvidia/gpus", bus), 0o755))
	}
	require.Equal(t, 2, CountNVIDIAGPUs(root))
}
