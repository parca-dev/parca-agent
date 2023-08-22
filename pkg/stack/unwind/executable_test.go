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
//

package unwind

import (
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestHasFramePointersInModernGolang(t *testing.T) {
	// This test works because we require Go > 1.18,
	// which compiles with frame pointers by default.
	hasFp, err := HasFramePointers("/proc/self/exe")
	require.NoError(t, err)
	require.True(t, hasFp)
}

func TestHasFramePointersInCApplication(t *testing.T) {
	hasFp, err := HasFramePointers("../../../testdata/out/x86/basic-cpp")
	require.NoError(t, err)
	require.False(t, hasFp)
}

func TestHasFramePointersCache(t *testing.T) {
	fpCache := NewHasFramePointersCache(log.NewNopLogger(), prometheus.NewRegistry())

	// Ensure that the cached results are correct.
	{
		hasFp, err := fpCache.HasFramePointers("../../../testdata/out/x86/basic-cpp")
		require.NoError(t, err)
		require.False(t, hasFp)
	}

	{
		hasFp, err := fpCache.HasFramePointers("../../../testdata/out/x86/basic-cpp")
		require.NoError(t, err)
		require.False(t, hasFp)
	}

	{
		hasFp, err := fpCache.HasFramePointers("/proc/self/exe")
		require.NoError(t, err)
		require.True(t, hasFp)
	}

	{
		hasFp, err := fpCache.HasFramePointers("/proc/self/exe")
		require.NoError(t, err)
		require.True(t, hasFp)
	}
}
