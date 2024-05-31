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
	"path/filepath"
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

func TestJava(t *testing.T) {
	ok, _, err := agent.PreflightChecks(false, false, false)
	require.Truef(t, ok, "preflight checks failed: %v", err)
	if err != nil {
		t.Logf("preflight checks passed but with errors: %v", err)
	}

	versionImages := map[string][]string{
		"11": {
			"eclipse-temurin:11",
			"amazoncorretto:11",
			// "amazoncorretto:11-alpine",
		},
		"17": {
			"eclipse-temurin:17",
			"amazoncorretto:17",
		},
		"18": {
			"eclipse-temurin:18",
			"amazoncorretto:18",
		},
		"19": {
			"eclipse-temurin:19",
			"amazoncorretto:19",
		},
		"20": {
			"eclipse-temurin:20",
			"amazoncorretto:20",
		},
		"21": {
			"eclipse-temurin:21",
			"amazoncorretto:21",
		},
	}

	tests := []struct {
		versionImages map[string][]string
		program       string
		want          []string
		wantErr       bool
	}{
		{
			versionImages: versionImages,
			program:       "testdata/cpuhog/Main.java",
			want:          []string{"<main>", "a1", "b1", "c1", "cpu", "<native code>"},
			wantErr:       false,
		},
		{
			versionImages: versionImages,
			program:       "testdata/Main.java",
			want:          []string{"<main>", "recurse_and_spin", "<native code>"},
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		for version, imageTags := range tt.versionImages {
			for _, imageTag := range imageTags {
				var (
					program = tt.program
					want    = tt.want
					name    = fmt.Sprintf("%s on java-%s", imageTag, program)
					version = version
				)
				t.Run(name, func(t *testing.T) {
					// Start a Java container.
					ctx, cancel := context.WithCancel(context.Background())
					t.Cleanup(cancel)

					java, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
						ContainerRequest: testcontainers.ContainerRequest{
							Image: imageTag,
							Files: []testcontainers.ContainerFile{
								{
									HostFilePath:      program,
									ContainerFilePath: "/" + filepath.Base(program),
									FileMode:          0o700,
								},
								{
									HostFilePath:      "testdata/build_and_run.sh",
									ContainerFilePath: "/build_and_run.sh",
									FileMode:          0o700,
								},
							},
							Cmd: []string{"sh", "/build_and_run.sh", strings.Split(filepath.Base(program), ".")[0]},
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
						profileStore = integration.NewTestAsyncProfileStore()
						logger       = logger.NewLogger("error", logger.LogFormatLogfmt, "parca-agent-tests")
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
						PythonUnwindingEnabled:            false,
						RubyUnwindingEnabled:              false,
						JavaUnwindingEnabled:              true,
						BPFVerboseLoggingEnabled:          false, // Enable for debugging.
						BPFEventsBufferSize:               8192,
						RateLimitUnwindInfo:               50,
						RateLimitProcessMappings:          50,
						RateLimitRefreshProcessInfo:       50,
					}
					profiler, err := integration.NewTestProfiler(logger, reg, ofp, profileStore, t.TempDir(), &conf,
						&relabel.Config{
							Action:       relabel.Keep,
							SourceLabels: model.LabelNames{"java"},
							Regex:        relabel.MustNewRegexp("true"),
						},
						&relabel.Config{
							Action:       relabel.Keep,
							SourceLabels: model.LabelNames{"java_version"},
							Regex:        relabel.MustNewRegexp(fmt.Sprintf("%s.*", version)),
						},
					)
					require.NoError(t, err)

					// TODO: make this 30s once the tests are passing.
					ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
					t.Cleanup(cancel)

					if conf.BPFVerboseLoggingEnabled {
						integration.LogTracingPipe(ctx, t, fmt.Sprintf("java-%d", state.Pid))
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
