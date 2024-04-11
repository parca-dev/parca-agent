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

package native

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log/level"
	pprofprofile "github.com/google/pprof/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/test/integration"
)

const (
	testdataPath = "../../../testdata"
)

type localSymbolizer struct {
	addr2line string
	timeout   time.Duration
}

func newLocalSymbolizer() *localSymbolizer {
	return &localSymbolizer{addr2line: "/usr/bin/addr2line", timeout: time.Second * 5}
}

func (ls *localSymbolizer) Symbolize(executable string, address uint64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ls.timeout)
	defer cancel()

	//nolint:gosec
	addr2lineCmd := exec.CommandContext(ctx, ls.addr2line, "--functions", "-e", executable, strconv.FormatUint(address, 16))
	addr2lineCmd.Wait()
	out, err := addr2lineCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CombinedOutput: %s, %w", out, err)
	}
	return strings.TrimSpace(strings.Split(string(out), "\n")[0]), nil
}

type localDemangler struct {
	filtProg string
	timeout  time.Duration
}

func newLocalDemangler() *localDemangler {
	return &localDemangler{filtProg: "/usr/bin/c++filt", timeout: time.Second * 5}
}

func (ld *localDemangler) Demangle(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ld.timeout)
	defer cancel()

	//nolint:gosec
	filtCmd := exec.CommandContext(ctx, ld.filtProg, name)
	filtCmd.Wait()
	out, err := filtCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CombinedOutput: %s %w", out, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func jitProfile(t *testing.T, profile *pprofprofile.Profile) [][]string {
	t.Helper()

	jitStacks := make([][]string, 0)
	for _, stack := range profile.Sample {
		jitStack := make([]string, 0)

		for _, frame := range stack.Location {
			// address := frame.Address
			file := frame.Mapping.File
			if file == "jit" {
				for _, line := range frame.Line {
					jitStack = append(jitStack, line.Function.Name)
				}
			}
		}

		jitStacks = append(jitStacks, jitStack)
	}

	return jitStacks
}

// symbolizeProfile symbolizes a given profile and optionally demangles the names.
//
// NOTE: this is intended for testing only, it's not complete nor performant, so it
// should never be used in production environments.
func symbolizeProfile(t *testing.T, profile *pprofprofile.Profile, demangle bool) [][]string {
	t.Helper()

	symbolizer := newLocalSymbolizer()
	demangler := newLocalDemangler()

	aggregatedStacks := make([][]string, 0)

	for _, stack := range profile.Sample {
		aggregatedStack := make([]string, 0, len(stack.Location))
		// check for the fake "unwind_failed" frames, and ignore
		if len(stack.Location) > 0 {
			lastLoc := stack.Location[len(stack.Location)-1]
			if len(lastLoc.Line) > 0 && lastLoc.Line[0].Function.Name == "unwind failed" {
				continue
			}
		}
		for _, frame := range stack.Location {
			address := frame.Address
			file := frame.Mapping.File

			if file == "jit" || strings.HasPrefix(file, "[") || file == "interpreter" {
				continue
			}

			funcName, err := symbolizer.Symbolize(file, address)
			require.NoError(t, err)

			if demangle {
				funcName, err = demangler.Demangle(funcName)
				require.NoError(t, err)
			}

			aggregatedStack = append(aggregatedStack, funcName)
		}
		aggregatedStacks = append(aggregatedStacks, aggregatedStack)
	}

	return aggregatedStacks
}

// TestCPUProfiler is the integration test for the CPU profiler. It
// uses an in-memory profile writer to be verify that the data we produce
// is correct.
func TestCPUProfiler(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		goleak.IgnoreTopFunction("github.com/baidubce/bce-sdk-go/util/log.NewLogger.func1"),
		goleak.IgnoreTopFunction("github.com/golang/glog.(*fileSink).flushDaemon"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)

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
		BPFVerboseLoggingEnabled:          true,
		BPFEventsBufferSize:               8192,
		RateLimitUnwindInfo:               50,
		RateLimitProcessMappings:          50,
		RateLimitRefreshProcessInfo:       50,
	})
	require.NoError(t, err)

	arch, err := integration.ChooseArch()
	require.NoError(t, err)
	// Test unwinding without frame pointers.
	noFramePointersCmd := exec.Command(filepath.Join(testdataPath, fmt.Sprintf("out/%s/basic-cpp-no-fp-with-debuginfo", arch)))
	require.NoError(t, noFramePointersCmd.Start())
	t.Cleanup(func() {
		noFramePointersCmd.Process.Kill()
	})
	dwarfUnwoundPid := noFramePointersCmd.Process.Pid

	// Test unwinding JIT without frame pointers in the AoT code.
	// TODO(sylfrena): Remove if condition once toy jit is added for arm64
	var jitPid int
	if arch == integration.Amd64 {
		jitCmd := exec.Command(filepath.Join(testdataPath, fmt.Sprintf("out/%s/basic-cpp-jit-no-fp", arch)))
		err = jitCmd.Start()
		require.NoError(t, err)
		t.Cleanup(func() {
			jitCmd.Process.Kill()
		})
		jitPid = jitCmd.Process.Pid
	}

	// Test unwinding with frame pointers.
	framePointersCmd := exec.Command(filepath.Join(testdataPath, fmt.Sprintf("out/%s/basic-go", arch)), "20000")
	err = framePointersCmd.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		framePointersCmd.Process.Kill()
	})
	fpUnwoundPid := framePointersCmd.Process.Pid

	level.Info(logger).Log("profileDuration", profileDuration)
	ctx, cancel := context.WithTimeout(context.Background(), profileDuration)
	t.Cleanup(cancel)

	ok, _, err := agent.PreflightChecks(false, false, false)
	require.Truef(t, ok, "preflight checks failed: %v", err)
	if err != nil {
		t.Logf("preflight checks passed but with errors: %v", err)
	}

	// Now that all the processes are running, start profiling them.
	err = profiler.Run(ctx)
	require.Equal(t, err, context.DeadlineExceeded)
	require.NotEmpty(t, profileStore.Samples)

	t.Run("dwarf unwinding", func(t *testing.T) {
		sample := profileStore.SampleForProcess(dwarfUnwoundPid, false)
		require.NotNil(t, sample)

		// Test basic profile structure.
		require.Less(t, sample.Profile.DurationNanos, profileDuration.Nanoseconds())
		require.Equal(t, "samples", sample.Profile.SampleType[0].Type)
		require.Equal(t, "count", sample.Profile.SampleType[0].Unit)

		require.NotEmpty(t, sample.Profile.Sample)
		require.NotEmpty(t, sample.Profile.Location)
		require.NotEmpty(t, sample.Profile.Mapping)

		// Test expected metadata.
		require.Equal(t, string(sample.Labels["comm"]), "basic-cpp-no-fp-with-debuginfo"[:15]) // comm is limited to 16 characters including NUL.
		require.True(t, strings.Contains(string(sample.Labels["executable"]), "basic-cpp-no-fp-with-debuginfo"))
		require.True(t, strings.HasPrefix(string(sample.Labels["compiler"]), "GCC"))
		require.NotEmpty(t, string(sample.Labels["kernel_release"]))
		require.NotEmpty(t, string(sample.Labels["cgroup_name"]))
		metadataPid, err := strconv.Atoi(string(sample.Labels["pid"]))
		require.NoError(t, err)
		require.Equal(t, dwarfUnwoundPid, metadataPid)
		metadataPpid, err := strconv.Atoi(string(sample.Labels["ppid"]))
		require.NoError(t, err)
		require.Equal(t, os.Getpid(), metadataPpid)

		// Test symbolized stacks.
		aggregatedStacks := symbolizeProfile(t, sample.Profile, true)
		require.NotEmpty(t, aggregatedStacks)

		integration.RequireAnyStackContains(t, aggregatedStacks, []string{"top2()", "c2()", "b2()", "a2()", "main"})
		integration.RequireAnyStackContains(t, aggregatedStacks, []string{"top1()", "c1()", "b1()", "a1()", "main"})
	})

	t.Run("fp unwinding", func(t *testing.T) {
		sample := profileStore.SampleForProcess(fpUnwoundPid, false)
		require.NotNil(t, sample)

		// Test basic profile structure.
		require.Less(t, sample.Profile.DurationNanos, profileDuration.Nanoseconds())
		require.Equal(t, "samples", sample.Profile.SampleType[0].Type)
		require.Equal(t, "count", sample.Profile.SampleType[0].Unit)

		require.NotEmpty(t, sample.Profile.Sample)
		require.NotEmpty(t, sample.Profile.Location)
		require.NotEmpty(t, sample.Profile.Mapping)

		// Test expected metadata.
		require.Equal(t, "basic-go", string(sample.Labels["comm"]))
		require.True(t, strings.Contains(string(sample.Labels["executable"]), "basic-go"))
		require.True(t, strings.HasPrefix(string(sample.Labels["compiler"]), "Go"))
		require.NotEmpty(t, string(sample.Labels["kernel_release"]))
		require.NotEmpty(t, string(sample.Labels["cgroup_name"]))
		metadataPid, err := strconv.Atoi(string(sample.Labels["pid"]))
		require.NoError(t, err)
		require.Equal(t, fpUnwoundPid, metadataPid)
		metadataPpid, err := strconv.Atoi(string(sample.Labels["ppid"]))
		require.NoError(t, err)
		require.Equal(t, os.Getpid(), metadataPpid)

		// Test symbolized stacks.
		aggregatedStacks := symbolizeProfile(t, sample.Profile, false)
		require.NotEmpty(t, aggregatedStacks)

		integration.RequireAnyStackContains(t, aggregatedStacks, []string{"time.Now", "main.main"})
	})

	t.Run("mixed mode unwinding", func(t *testing.T) {
		if arch == integration.Amd64 {
			sample := profileStore.SampleForProcess(jitPid, false)
			require.NotNil(t, sample)

			// Test basic profile structure.
			require.Less(t, sample.Profile.DurationNanos, profileDuration.Nanoseconds())
			require.Equal(t, "samples", sample.Profile.SampleType[0].Type)
			require.Equal(t, "count", sample.Profile.SampleType[0].Unit)

			require.NotEmpty(t, sample.Profile.Sample)
			require.NotEmpty(t, sample.Profile.Location)
			require.NotEmpty(t, sample.Profile.Mapping)

			// Test expected metadata.
			require.Equal(t, string(sample.Labels["comm"]), "basic-cpp-jit-no-fp"[:15]) // comm is limited to 16 characters including NUL.
			require.True(t, strings.Contains(string(sample.Labels["executable"]), "basic-cpp-jit-no-fp"))
			require.True(t, strings.HasPrefix(string(sample.Labels["compiler"]), "GCC"))
			require.NotEmpty(t, string(sample.Labels["kernel_release"]))
			require.NotEmpty(t, string(sample.Labels["cgroup_name"]))
			metadataPid, err := strconv.Atoi(string(sample.Labels["pid"]))
			require.NoError(t, err)
			require.Equal(t, jitPid, metadataPid)
			metadataPpid, err := strconv.Atoi(string(sample.Labels["ppid"]))
			require.NoError(t, err)
			require.Equal(t, os.Getpid(), metadataPpid)

			// Test symbolized stacks.
			aggregatedStacks := symbolizeProfile(t, sample.Profile, true)
			require.NotEmpty(t, aggregatedStacks)
			integration.RequireAnyStackContains(t, aggregatedStacks, []string{"aot_top()", "aot2()", "aot1()", "aot()", "main"})

			// Test jitted stacks.
			jitStacks := jitProfile(t, sample.Profile)
			integration.RequireAnyStackContains(t, jitStacks, []string{"jit_top", "jit_middle"})
		}
	})

	t.Run("unwinder metrics work", func(t *testing.T) {
		addr := "localhost:7071"

		// Spawn the HTTP server with the /metrics Prometheus handler.
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

		srv := &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  1 * time.Second,
			WriteTimeout: 1 * time.Second,
		}
		go srv.ListenAndServe()
		t.Cleanup(func() {
			srv.Shutdown(context.Background())
		})

		url := fmt.Sprintf("http://%s/metrics", addr)
		require.NoError(t, integration.WaitForServer(url))

		resp, err := http.Get(url) //nolint: noctx
		require.NoError(t, err)
		t.Cleanup(func() {
			resp.Body.Close()
		})

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		metrics := integration.ParsePrometheusMetricsEndpoint(string(body))
		require.NotEmpty(t, metrics)

		// TODO: fix this assertion, all the BPF map metrics are zero but I am not sure why.
		// i, err := strconv.Atoi(metrics[`parca_agent_native_unwinder_success_total{unwinder="dwarf"}`])
		// require.NoError(t, err)
		// require.Greater(t, i, 0)
	})
}
