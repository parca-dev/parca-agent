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

package nodejs

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

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/test/integration"
)

func TestNodeJS(t *testing.T) {
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
				"18": "18-slim",
				"20": "20-slim",
				"21": "21-slim",
			},
			program: "testdata/cpu_hog.js",
			want: []string{
				"JS:~",
				"JS:~executeUserEntryPoint",
				"JS:~Module._load",
				"JS:~Module.load",
				"JS:~Module._extensions..js",
				"JS:~Module._compile",
				"JS:~",
				"JS:^runLoop",
				"JS:^a1",
				"JS:^b1",
				"JS:^c1",
				"JS:^cpu",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		for version, imageTag := range tt.images {
			var (
				program = tt.program
				want    = tt.want
				name    = fmt.Sprintf("%s on nodejs-%s", imageTag, version)
				version = version
			)
			t.Run(name, func(t *testing.T) {
				// Start a Node.js container.
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)

				nodejs, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
					ContainerRequest: testcontainers.ContainerRequest{
						Image: fmt.Sprintf("node:%s", imageTag),
						Files: []testcontainers.ContainerFile{
							{
								HostFilePath:      program,
								ContainerFilePath: "/cpu_hog.js",
								FileMode:          0o700,
							},
						},
						Cmd: []string{"node", "--no-opt", "--perf-basic-prof-only-functions", "--interpreted-frames-native-stack", "/cpu_hog.js"},
					},
					Started: true,
				})
				require.NoError(t, err)

				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()

					err := nodejs.Terminate(ctx)
					if err != nil {
						require.ErrorIs(t, err, context.DeadlineExceeded)
					}
				})

				state, err := nodejs.State(ctx)
				require.NoError(t, err)

				if !state.Running {
					t.Logf("node.js (%s) is not running", name)
				}

				t.Logf("node.js (%s) is running with pid %d", version, state.Pid)

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
					DWARFUnwindingMixedModeEnabled:    true,
					PythonUnwindingEnabled:            false,
					RubyUnwindingEnabled:              false,
					BPFVerboseLoggingEnabled:          false, // Enable for debugging.
					BPFEventsBufferSize:               8192,
					RateLimitUnwindInfo:               50,
					RateLimitProcessMappings:          50,
					RateLimitRefreshProcessInfo:       50,
				},
					&relabel.Config{
						Action:       relabel.Keep,
						SourceLabels: model.LabelNames{"nodejs"},
						Regex:        relabel.MustNewRegexp("true"),
					},
					&relabel.Config{
						Action:       relabel.Keep,
						SourceLabels: model.LabelNames{"nodejs_version"},
						Regex:        relabel.MustNewRegexp(fmt.Sprintf("%s.*", version)),
					},
				)
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

				integration.RequireAnyStackContains(t, aggregatedStack, want)
			})
		}
	}
}
