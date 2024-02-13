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

package python

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/test/integration"
)

func TestPython(t *testing.T) {
	tests := []struct {
		images  []string
		program string
		want    []string
		wantErr bool
	}{
		{
			images: []string{
				"2.7.18-slim",
				"3.3.7-slim",
				"3.4.8-slim",
				"3.5.5-slim",
				"3.6.6-slim",
				"3.7.0-slim",
				"3.8.0-slim",
				"3.9.5-slim",
				"3.10.0-slim",
				"3.11.0-slim",
			},
			program: "testdata/cpu_hog.py",
			want:    []string{"<module>", "a1", "b1", "c1", "cpu"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		for _, imageTag := range tt.images {
			var (
				program = tt.program
				want    = tt.want
				name    = fmt.Sprintf("%s on python-%s", imageTag, program)
			)
			t.Run(name, func(t *testing.T) {
				// Start a python container.
				ctx := context.Background()
				python, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
					ContainerRequest: testcontainers.ContainerRequest{
						Image: fmt.Sprintf("python:%s", imageTag),
						Files: []testcontainers.ContainerFile{
							{
								HostFilePath:      program,
								ContainerFilePath: "/test.py",
								FileMode:          0o700,
							},
						},
						Cmd: []string{"python", "/test.py"},
					},
					Started: true,
				})
				require.NoError(t, err)

				t.Cleanup(func() {
					err := python.Terminate(ctx)
					if err != nil {
						require.ErrorIs(t, err, context.DeadlineExceeded)
					}
				})

				state, err := python.State(ctx)
				require.NoError(t, err)

				if !state.Running {
					t.Logf("python (%s) is not running", name)
				}

				// Start the agent.
				var (
					profileStore    = integration.NewTestProfileStore()
					profileDuration = integration.ProfileDuration()

					logger = logger.NewLogger("error", logger.LogFormatLogfmt, "parca-agent-tests")
					reg    = prometheus.NewRegistry()
					ofp    = objectfile.NewPool(logger, reg, "", 10, 0)
				)
				t.Cleanup(func() {
					ofp.Close()
				})

				profiler, err := integration.NewTestProfiler(logger, reg, ofp, profileStore, t.TempDir(), &cpu.Config{
					ProfilingDuration:                 1 * time.Second,
					ProfilingSamplingFrequency:        uint64(27),
					PerfEventBufferPollInterval:       250,
					PerfEventBufferProcessingInterval: 100,
					PerfEventBufferWorkerCount:        8,
					MemlockRlimit:                     uint64(4000000),
					DebugProcessNames:                 []string{},
					DWARFUnwindingDisabled:            false,
					DWARFUnwindingMixedModeEnabled:    false,
					PythonUnwindingEnabled:            true,
					RubyUnwindingEnabled:              false,
					BPFVerboseLoggingEnabled:          false, // Enable for debugging.
					BPFEventsBufferSize:               8192,
					RateLimitUnwindInfo:               50,
					RateLimitProcessMappings:          50,
					RateLimitRefreshProcessInfo:       50,
				},
					&relabel.Config{
						Action:       relabel.Keep,
						SourceLabels: model.LabelNames{"comm"},
						Regex:        relabel.MustNewRegexp("python"),
					},
				)
				require.NoError(t, err)

				ctx, cancel := context.WithTimeout(context.Background(), profileDuration)
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

				integration.RequireAnyStackContains(t, aggregatedStack, want)
			})
		}
	}
}
