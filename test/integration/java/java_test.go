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

package java

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/test/integration"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestJava(t *testing.T) {
	ok, _, err := agent.PreflightChecks(false, false, false)
	require.Truef(t, ok, "preflight checks failed: %v", err)
	if err != nil {
		t.Logf("preflight checks passed but with errors: %v", err)
	}

	tests := []struct {
		images  map[string]string
		program string
		want    []string
		wantErr bool
	}{
		{
			images: map[string]string{
				"11": "11",
			},
			program: "testdata/Main.java",
			want:    []string{"<main>", "a1", "b1", "c1", "cpu", "<native code>"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		for version, imageTag := range tt.images {
			var (
				program = tt.program
				want    = tt.want
				name    = fmt.Sprintf("%s on java-%s", imageTag, program)
				version = version
			)
			_ = want
			_ = version
			t.Run(name, func(t *testing.T) {
				// Start a Ruby container.
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)

				java, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
					ContainerRequest: testcontainers.ContainerRequest{
						//						Image: fmt.Sprintf("eclipse-temurin:%s", imageTag),
						Image: fmt.Sprintf("amazoncorretto:%s", imageTag),
						//Image: fmt.Sprintf("amazoncorretto:%s-alpine", imageTag),
						Files: []testcontainers.ContainerFile{
							{
								HostFilePath:      program,
								ContainerFilePath: "/Main.java",
								FileMode:          0o700,
							},
							{
								HostFilePath:      "testdata/test.sh",
								ContainerFilePath: "/test.sh",
								FileMode:          0o700,
							},
						},
						Cmd: []string{"sh", "test.sh"},
					},
					Started: true,
				})
				require.NoError(t, err)

				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()

					err := java.Terminate(ctx)
					if err != nil {
						require.ErrorIs(t, err, context.DeadlineExceeded)
					}
				})

				state, err := java.State(ctx)
				require.NoError(t, err)

				if !state.Running {
					t.Logf("java (%s) is not running", name)
				}

				t.Logf("java (%s) is running with pid %d (%v)", version, state.Pid, state)

				// Start the agent.
				var (
					profileStore    = integration.NewTestProfileStore()
					profileDuration = integration.ProfileDuration()

					logger = logger.NewLogger("debug", logger.LogFormatLogfmt, "parca-agent-tests")
					reg    = prometheus.NewRegistry()
					ofp    = objectfile.NewPool(logger, reg, "", 100, 0)
				)
				// Java requires more time for agent to populate mappings
				if !integration.IsRunningOnCI() {
					profileDuration = profileDuration * 3
				}
				t.Cleanup(func() {
					ofp.Close()
				})
				profiler, err := integration.NewTestProfiler(logger, reg, ofp, profileStore, t.TempDir(), &cpu.Config{
					ProfilingDuration:                 10 * time.Second,
					ProfilingSamplingFrequency:        uint64(27),
					PerfEventBufferPollInterval:       250,
					PerfEventBufferProcessingInterval: 100,
					PerfEventBufferWorkerCount:        8,
					MemlockRlimit:                     uint64(4000000),
					DebugProcessNames:                 []string{"java"},
					DWARFUnwindingDisabled:            false,
					DWARFUnwindingMixedModeEnabled:    true,
					PythonUnwindingEnabled:            false,
					RubyUnwindingEnabled:              false,
					BPFVerboseLoggingEnabled:          true, // Enable for debugging.
					BPFEventsBufferSize:               8192,
					RateLimitUnwindInfo:               50,
					RateLimitProcessMappings:          50,
					RateLimitRefreshProcessInfo:       50,
				})
				require.NoError(t, err)

				ctx, cancel = context.WithTimeout(context.Background(), profileDuration)
				t.Cleanup(cancel)

				require.Equal(t, profiler.Run(ctx), context.DeadlineExceeded)
				require.NotEmpty(t, profileStore.Samples)

				sample := profileStore.SampleForProcess(state.Pid, false)
				require.NotNil(t, sample)

				require.Less(t, sample.Profile.DurationNanos, profileDuration.Nanoseconds())
				require.Equal(t, "samples", sample.Profile.SampleType[0].Type)
				require.Equal(t, "count", sample.Profile.SampleType[0].Unit)

				require.NotEmpty(t, sample.Profile.Sample)
				require.NotEmpty(t, sample.Profile.Location)
				require.NotEmpty(t, sample.Profile.Mapping)

				aggregatedStack, err := integration.AggregateStacks(sample.Profile)
				require.NoError(t, err)
				t.Log(aggregatedStack)
				_ = aggregatedStack
			})
		}
	}
}
