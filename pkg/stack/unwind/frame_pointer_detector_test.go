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
//

package unwind

import (
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

func TestHasFramePointersInModernGolang(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	fpd := NewFramePointerDetector(
		logger,
		reg,
		runtime.NewCompilerInfoManager(logger, reg, objFilePool),
	)

	// This test works because we require Go > 1.18,
	// which compiles with frame pointers by default.
	res, err := fpd.hasFramePointers("/proc/self/exe")
	require.NoError(t, err)
	require.True(t, res.OnlyMainExecutable)
	require.False(t, res.AllMappings)
}

func TestHasFramePointersInCApplication(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	fpd := NewFramePointerDetector(
		logger,
		reg,
		runtime.NewCompilerInfoManager(logger, reg, objFilePool),
	)

	res, err := fpd.hasFramePointers("../../../testdata/out/x86/basic-cpp")
	require.NoError(t, err)
	require.False(t, res.AllMappings)
}

func TestHasFramePointersCache(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	fpd := NewFramePointerDetector(
		logger,
		reg,
		runtime.NewCompilerInfoManager(logger, reg, objFilePool),
	)

	// Ensure that the cached results are correct.
	{
		res, err := fpd.HasFramePointers("../../../testdata/out/x86/basic-cpp")
		require.NoError(t, err)
		require.False(t, res.AllMappings)
	}

	{
		res, err := fpd.HasFramePointers("../../../testdata/out/x86/basic-cpp")
		require.NoError(t, err)
		require.False(t, res.AllMappings)
	}

	{
		res, err := fpd.HasFramePointers("/proc/self/exe")
		require.NoError(t, err)
		require.True(t, res.AllMappings)
	}

	{
		res, err := fpd.HasFramePointers("/proc/self/exe")
		require.NoError(t, err)
		require.True(t, res.AllMappings)
	}
}
