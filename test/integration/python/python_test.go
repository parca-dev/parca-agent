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
	"runtime"
	"strconv"
	"strings"
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

func TestPython(t *testing.T) {
	ok, _, err := agent.PreflightChecks(false, false, false)
	require.Truef(t, ok, "preflight checks failed: %v", err)
	if err != nil {
		t.Logf("preflight checks passed but with errors: %v", err)
	}

	tests := []struct {
		versionImages map[string][]string
		program       string
		want          []string
		wantErr       bool
	}{
		{
			versionImages: map[string][]string{
				"2.7": {
					"2.7.18-slim",
					"2.7.18-alpine",
				},
				"3.3": {
					"3.3.7-slim",
					"3.3.7-alpine",
				},
				"3.4": {
					"3.4.8-slim",
					"3.4.8-alpine",
				},
				"3.5": {
					"3.5.5-slim",
					"3.5.5-alpine",
				},
				"3.6": {
					"3.6.6-slim",
					"3.6.6-alpine",
				},
				"3.7": {
					"3.7.0-slim",
					"3.7.17-slim",
					"3.7.17-alpine",
				},
				"3.8": {
					"3.8.0-slim",
					"3.8.19-slim",
					"3.8.19-alpine",
				},
				"3.9": {
					"3.9.5-slim",
					"3.9.19-slim",
					"3.9.19-alpine",
				},
				"3.10": {
					"3.10.0-slim",
					"3.10.14-slim",
					"3.10.14-alpine",
				},
				"3.11": {
					"3.11.0-slim",
					"3.11.8-slim",
					"3.11.8-alpine",
				},
				"3.12": {
					"3.12.2-slim",
					"3.12.2-alpine",
				},
				"3.13": {
					"3.13.0a4-slim",
					"3.13.0a4-alpine",
				},
			},
			program: "testdata/cpu_hog.py",
			want:    []string{"<module>", "a1", "b1", "c1", "cpu"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		for version, imageTags := range tt.versionImages {
			for _, imageTag := range imageTags {
				var (
					program = tt.program
					want    = tt.want
					name    = fmt.Sprintf("%s on python-%s", imageTag, program)
					version = version
				)
				t.Run(name, func(t *testing.T) {
					// Start a python container.
					ctx, cancel := context.WithCancel(context.Background())
					t.Cleanup(cancel)
					imageName := "python:" + imageTag
					python, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
						ContainerRequest: testcontainers.ContainerRequest{
							FromDockerfile: testcontainers.FromDockerfile{
								Context: "testdata",
								Tag:     imageTag,
								Repo:    "python-test",
								BuildArgs: map[string]*string{
									"PY_IMAGE": &imageName,
								},
								KeepImage: true,
							},
						},
						Started: true,
					})

					if err != nil && runtime.GOARCH == "arm64" && strings.Contains(err.Error(), "No such image: python-test:3.3.7-alpine") {
						// There's no alpine images for python 3.3 on arm64 for some reason.
						t.Skip()
					}
					require.NoError(t, err)

					t.Cleanup(func() {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()

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

					t.Logf("python (%s) is running with pid %d", version, state.Pid)

					// Start the agent.
					var (
						profileStore = integration.NewTestAsyncProfileStore()
						logger       = logger.NewLogger("info", logger.LogFormatLogfmt, "parca-agent-tests")
						reg          = prometheus.NewRegistry()
						ofp          = objectfile.NewPool(logger, reg, "", 100, 10*time.Second)
					)
					t.Cleanup(func() {
						profileStore.Close()
						ofp.Close()
					})
					conf := cpu.Config{
						ProfilingDuration:                 1 * time.Second,
						ProfilingSamplingFrequency:        uint64(27),
						PerfEventBufferPollInterval:       250,
						PerfEventBufferProcessingInterval: 100,
						PerfEventBufferWorkerCount:        8,
						MemlockRlimit:                     uint64(4000000),
						DebugProcessNames:                 []string{},
						DWARFUnwindingDisabled:            false,
						DWARFUnwindingMixedModeEnabled:    true,
						PythonUnwindingEnabled:            true,
						RubyUnwindingEnabled:              false,
						BPFVerboseLoggingEnabled:          false, // Enable for debugging.
						BPFEventsBufferSize:               8192,
						RateLimitUnwindInfo:               50,
						RateLimitProcessMappings:          50,
						RateLimitRefreshProcessInfo:       50,
					}
					profiler, err := integration.NewTestProfiler(logger, reg, ofp, profileStore, t.TempDir(), &conf,
						&relabel.Config{
							Action:       relabel.Keep,
							SourceLabels: model.LabelNames{"python"},
							Regex:        relabel.MustNewRegexp("true"),
						},
						&relabel.Config{
							Action:       relabel.Keep,
							SourceLabels: model.LabelNames{"python_version"},
							Regex:        relabel.MustNewRegexp(fmt.Sprintf("%s.*", version)),
						},
					)
					require.NoError(t, err)

					ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
					t.Cleanup(cancel)

					if conf.BPFVerboseLoggingEnabled {
						integration.LogTracingPipe(ctx, t, fmt.Sprintf("python-%d", state.Pid))
					}

					integration.RunAndAwaitSamples(t, ctx, profiler, profileStore, func(t *testing.T, s integration.Sample) bool {
						t.Helper()
						foundPid, err := strconv.Atoi(string(s.Labels["pid"]))
						if err != nil {
							t.Fatal("label pid is not a valid integer")
						}
						if foundPid != state.Pid {
							return false
						}

						require.Equal(t, "samples", s.Profile.SampleType[0].Type)
						require.Equal(t, "count", s.Profile.SampleType[0].Unit)

						require.NotEmpty(t, s.Profile.Sample)
						require.NotEmpty(t, s.Profile.Location)
						require.NotEmpty(t, s.Profile.Mapping)

						aggregatedStack, err := integration.AggregateStacks(s.Profile)
						require.NoError(t, err)

						if integration.AnyStackContains(aggregatedStack, want) {
							cancel()
							t.Log("Got ", want)
							return true
						}
						return false
					})
				})
			}
		}
	}
}
