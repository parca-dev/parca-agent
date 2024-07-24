// Copyright 2024 The Parca Authors
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

package bpfprograms_test

import (
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
)

func SetUpBpfProgram(t *testing.T) (*bpf.Module, error) {
	t.Helper()
	logger := logger.NewLogger("debug", logger.LogFormatLogfmt, "parca-cpu-test")

	memLock := uint64(1200 * 1024 * 1024) // ~1.2GiB

	reg := prometheus.NewRegistry()
	ofp := objectfile.NewPool(logger, reg, "", 10, 0)
	m, _, err := cpu.LoadBPFModules(logger, reg, memLock, cpu.Config{
		DWARFUnwindingMixedModeEnabled: true,
		DWARFUnwindingDisabled:         false,
		BPFVerboseLoggingEnabled:       false,
		BPFEventsBufferSize:            8192,
		PythonUnwindingEnabled:         true,
		RubyUnwindingEnabled:           true,
		RateLimitUnwindInfo:            50,
		RateLimitProcessMappings:       50,
		RateLimitRefreshProcessInfo:    50,
	}, ofp, nil)
	require.NoError(t, err)
	require.NotNil(t, m)

	return m, err
}

func TestPrograms(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
}
