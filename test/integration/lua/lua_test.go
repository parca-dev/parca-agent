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
//

package lua

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/test/integration"
)

func TestLua(t *testing.T) {
	ok, _, err := agent.PreflightChecks(false, false, false)
	require.Truef(t, ok, "preflight checks failed: %v", err)
	if err != nil {
		t.Logf("preflight checks passed but with errors: %v", err)
	}

	tests := []struct {
		name          string
		image         string
		program       string
		want          []string
		wantErr       bool
		enableUprobes bool
	}{
		{
			name:          "openresty-latest-uprobe",
			image:         "openresty/openresty:latest",
			program:       "testdata/fib.conf",
			want:          []string{"main", "Fibonacci::naive", "inner"},
			wantErr:       false,
			enableUprobes: true,
		},
		{
			name:          "openresty-latest",
			image:         "openresty/openresty:latest",
			program:       "testdata/fib.conf",
			want:          []string{"main", "Fibonacci::naive", "inner"},
			wantErr:       false,
			enableUprobes: false,
		},
		{
			name:          "openresty-1_21_4_1",
			image:         "openresty/openresty:1.21.4.1-0-jammy",
			program:       "testdata/fib.conf",
			want:          []string{"main", "Fibonacci::naive", "inner"},
			wantErr:       false,
			enableUprobes: false,
		},
		{
			name:          "openresty-1_17_8_1-alpine",
			image:         "openresty/openresty:1.17.8.1-alpine",
			program:       "testdata/fib.conf",
			want:          []string{"main", "Fibonacci::naive", "inner"},
			wantErr:       false,
			enableUprobes: false,
		},
		{
			name:          "openresty-1_17_8_1-alpine-call",
			image:         "openresty/openresty:1.17.8.1-alpine",
			program:       "testdata/call.conf",
			want:          []string{"main", "Fibonacci::naive", "inner"},
			wantErr:       false,
			enableUprobes: false,
		},
		{
			name:          "openresty-1_17_8_1-alpine-nojit",
			image:         "openresty/openresty:1.17.8.1-alpine",
			program:       "testdata/nojit.conf",
			want:          []string{"main", "Fibonacci::naive", "inner"},
			wantErr:       false,
			enableUprobes: false,
		},
	}
	for _, tt := range tests {
		var (
			program = tt.program
			want    = tt.want
			name    = tt.name
			version = "latest"
		)
		t.Run(name, func(t *testing.T) {
			// Start a openresty container.
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			lua, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
				ContainerRequest: testcontainers.ContainerRequest{
					Image:        tt.image,
					ExposedPorts: []string{"80"},
					Files: []testcontainers.ContainerFile{
						{
							HostFilePath:      "testdata/nginx.conf",
							ContainerFilePath: "/usr/local/openresty/nginx/conf/nginx.conf",
						},
						{
							HostFilePath:      program,
							ContainerFilePath: "/etc/nginx/conf.d/default.conf",
						},
					},
				},
				Started: true,
			})
			require.NoError(t, err)

			host, err := lua.Host(ctx)
			require.NoError(t, err)

			port, err := lua.MappedPort(ctx, "80")
			require.NoError(t, err)

			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					url := "http://" + net.JoinHostPort(host, port.Port())
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
					if err != nil {
						t.Log(err)
					}
					res, err := http.DefaultClient.Do(req)
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						t.Log(err)
						continue
					}
					defer res.Body.Close()
					body, err := io.ReadAll(res.Body)
					if err != nil {
						t.Log(err)
					}
					showContents := false
					if showContents {
						t.Log(string(body))
					}
				}
			}()

			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				err := lua.Terminate(ctx)
				if err != nil {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			})

			state, err := lua.State(ctx)
			require.NoError(t, err)

			if !state.Running {
				t.Logf("lua (%s) is not running", name)
			}

			pid := state.Pid
			t.Logf("lua (%s) is running with pid %d", version, pid)

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
				PythonUnwindingEnabled:            false,
				RubyUnwindingEnabled:              false,
				LuaUnwindingEnabled:               true,
				LuaEnableUprobes:                  tt.enableUprobes,
				BPFVerboseLoggingEnabled:          true, // Enable for debugging.
				BPFEventsBufferSize:               8192,
				RateLimitUnwindInfo:               50,
				RateLimitProcessMappings:          50,
				RateLimitRefreshProcessInfo:       50,
			}
			profiler, err := integration.NewTestProfiler(logger, reg, ofp, profileStore, t.TempDir(), &conf)
			require.NoError(t, err)

			ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
			t.Cleanup(cancel)

			if conf.BPFVerboseLoggingEnabled {
				integration.LogTracingPipe(ctx, t, "lua:")
			}

			integration.RunAndAwaitSamples(t, ctx, profiler, profileStore, func(t *testing.T, s integration.Sample) bool {
				t.Helper()
				foundPid, err := strconv.Atoi(string(s.Labels["ppid"]))
				if err != nil {
					t.Log("label ppid is not a valid integer", err, string(s.Labels["ppid"]))
					return false
				}
				if foundPid != pid {
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
