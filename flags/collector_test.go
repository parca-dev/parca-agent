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

package flags

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseArgs(t *testing.T, args ...string) Flags {
	t.Helper()
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	// The kernel minimum is the host's business, not this test's.
	os.Args = append([]string{"parca-agent", "--ignore-unsafe-kernel-version"}, args...)
	f, err := Parse()
	require.NoError(t, err)
	return f
}

// The collector's Validate rejects zero values parca-agent has no flag for,
// so the defaults must fill every field it checks.
func TestCollectorConfigAcceptsDefaults(t *testing.T) {
	require.NoError(t, parseArgs(t).CollectorConfig().Validate())
}

func TestCollectorConfigRejectsBadTracerSettings(t *testing.T) {
	for _, args := range [][]string{
		{"--bpf-map-scale-factor=9"},
		{"--bpf-map-scale-factor=-1"},
		{"--bpf-verifier-log-level=3"},
		{"--profiling-probabilistic-interval=30s"},
		{"--profiling-probabilistic-threshold=0"},
		{"--profiling-cpu-sampling-frequency=0"},
	} {
		t.Run(args[0], func(t *testing.T) {
			require.Error(t, parseArgs(t, args...).CollectorConfig().Validate())
		})
	}
}
