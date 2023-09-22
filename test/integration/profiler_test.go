// Copyright 2022-2023 The Parca Authors
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

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	pprofprofile "github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/goleak"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/namespace"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
	parcapprof "github.com/parca-dev/parca-agent/pkg/pprof"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/pkg/vdso"
)

type Sample struct {
	labels  model.LabelSet
	profile *pprofprofile.Profile
}

type TestProfileStore struct {
	samples []Sample
}

func NewTestProfileStore() *TestProfileStore {
	return &TestProfileStore{samples: make([]Sample, 0)}
}

func (tpw *TestProfileStore) Store(_ context.Context, labels model.LabelSet, profile profile.Writer, _ []*profilestorepb.ExecutableInfo) error {
	p, ok := profile.(*pprofprofile.Profile)
	if !ok {
		return fmt.Errorf("profile is not a pprof profile")
	}
	tpw.samples = append(tpw.samples, Sample{
		labels:  labels,
		profile: p,
	})
	return nil
}

// SampleForProcess returns the first or last matching sample for a given
// PID.
func (tpw *TestProfileStore) SampleForProcess(pid int, last bool) *Sample {
	for i := range tpw.samples {
		var sample Sample
		if last {
			sample = tpw.samples[len(tpw.samples)-1-i]
		} else {
			sample = tpw.samples[i]
		}

		foundPid, err := strconv.Atoi(string(sample.labels["pid"]))
		if err != nil {
			panic("label pid is not a valid integer")
		}

		if foundPid == pid {
			return &sample
		}
	}

	return nil
}

type LocalSymbolizer struct {
	addr2line string
	timeout   time.Duration
}

func NewLocalSymbolizer() *LocalSymbolizer {
	return &LocalSymbolizer{addr2line: "/usr/bin/addr2line", timeout: time.Second * 5}
}

func (ls *LocalSymbolizer) Symbolize(executable string, address uint64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ls.timeout)
	defer cancel()

	//nolint:gosec
	addr2lineCmd := exec.CommandContext(ctx, ls.addr2line, "--functions", "-e", executable, fmt.Sprintf("%x", address))
	addr2lineCmd.Wait()
	out, err := addr2lineCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("CombinedOutput: %s, %w", out, err)
	}
	return strings.TrimSpace(strings.Split(string(out), "\n")[0]), nil
}

type LocalDemangler struct {
	filtProg string
	timeout  time.Duration
}

func NewLocalDemangler() *LocalDemangler {
	return &LocalDemangler{filtProg: "/usr/bin/c++filt", timeout: time.Second * 5}
}

func (ld *LocalDemangler) Demangle(name string) (string, error) {
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

	symbolizer := NewLocalSymbolizer()
	demangler := NewLocalDemangler()

	aggregatedStacks := make([][]string, 0)
	for _, stack := range profile.Sample {
		aggregatedStack := make([]string, 0, len(stack.Location))
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

// anyStackContains returns whether the passed string slice is contained
// in any of the slice of string slices. This is used to ensure that a
// stacktrace is contained in a given profile.
func anyStackContains(foundStacks [][]string, stack []string) bool {
	foundEqualSubslice := false

	for _, foundStack := range foundStacks {
		if len(stack) > len(foundStack) {
			continue
		}

		for s := 0; s < len(foundStack)-len(stack)+1; s++ {
			equal := true
			subSlice := foundStack[s:]
			for i := range stack {
				if stack[i] != subSlice[i] {
					equal = false
					break
				}
			}
			if equal {
				foundEqualSubslice = true
				break
			}
		}
	}

	return foundEqualSubslice
}

func requireAnyStackContains(t *testing.T, foundStacks [][]string, stack []string) {
	t.Helper()

	if !anyStackContains(foundStacks, stack) {
		t.Fatal("The stack", stack, "is not contained in any of", foundStacks)
	}
}

func prepareProfiler(t *testing.T, profileStore profiler.ProfileStore, logger log.Logger, tempDir string) (*cpu.CPU, *prometheus.Registry, *objectfile.Pool) {
	t.Helper()

	loopDuration := 1 * time.Second
	disableJit := false
	frequency := uint64(27)
	reg := prometheus.NewRegistry()
	pfs, err := procfs.NewDefaultFS()
	require.NoError(t, err)
	bpfProgramLoaded := make(chan bool, 1)
	memlockRlimit := uint64(4000000)

	ofp := objectfile.NewPool(logger, reg, 10, 0)

	var vdsoCache parcapprof.VDSOSymbolizer
	vdsoCache, err = vdso.NewCache(reg, ofp)
	if err != nil {
		t.Log("VDSO cache not available, using noop cache")
		vdsoCache = vdso.NoopCache{}
	}

	dbginfo := debuginfo.NoopDebuginfoManager{}
	labelsManager := labels.NewManager(
		logger,
		trace.NewNoopTracerProvider().Tracer("test"),
		reg,
		[]metadata.Provider{
			metadata.Compiler(logger, reg, ofp),
			metadata.Process(pfs),
			metadata.System(),
			metadata.PodHosts(),
		},
		[]*relabel.Config{},
		false,
		loopDuration,
	)

	profiler := cpu.NewCPUProfiler(
		logger,
		reg,
		process.NewInfoManager(
			logger,
			trace.NewNoopTracerProvider().Tracer("test"),
			reg,
			pfs,
			ofp,
			process.NewMapManager(reg, pfs, ofp),
			dbginfo,
			labelsManager,
			loopDuration,
			loopDuration,
			false, // interpreter unwinding enabled
		),
		parcapprof.NewManager(
			logger,
			reg,
			ksym.NewKsym(logger, reg, tempDir),
			perf.NewPerfMapCache(logger, reg, namespace.NewCache(logger, reg, loopDuration), loopDuration),
			perf.NewJitdumpCache(logger, reg, loopDuration),
			vdsoCache,
			disableJit,
		),
		profileStore,
		&cpu.Config{
			ProfilingDuration:                 loopDuration,
			ProfilingSamplingFrequency:        frequency,
			PerfEventBufferPollInterval:       250,
			PerfEventBufferProcessingInterval: 100,
			PerfEventBufferWorkerCount:        8,
			MemlockRlimit:                     memlockRlimit,
			DebugProcessNames:                 []string{},
			DWARFUnwindingDisabled:            false,
			DWARFUnwindingMixedModeEnabled:    false,
			PythonUnwindingEnabled:            false,
			RubyUnwindingEnabled:              false,
			BPFVerboseLoggingEnabled:          true,
			BPFEventsBufferSize:               8192,
		},
		bpfProgramLoaded,
	)

	// Wait for the BPF program to be loaded.
	for len(bpfProgramLoaded) > 0 {
		<-bpfProgramLoaded
	}

	return profiler, reg, ofp
}

func TestAnyStackContains(t *testing.T) {
	// Edge cases.
	require.True(t, anyStackContains([][]string{{"a", "b"}}, []string{}))
	require.False(t, anyStackContains([][]string{{}}, []string{"a", "b"}))

	// Equality and containment.
	require.True(t, anyStackContains([][]string{{"a", "b"}}, []string{"a", "b"}))
	require.True(t, anyStackContains([][]string{{"_", "a", "b"}}, []string{"a", "b"}))
	require.True(t, anyStackContains([][]string{{"a", "b"}, {"a", "c"}}, []string{"a", "c"}))
	require.True(t, anyStackContains([][]string{{"main"}, {"a", "b"}}, []string{"a", "b"}))

	// Sad path.
	require.False(t, anyStackContains([][]string{{"a", "b"}}, []string{"a", "c"}))
	require.False(t, anyStackContains([][]string{{"_", "a", "b"}}, []string{"a", "c"}))
	require.False(t, anyStackContains([][]string{{"a", "b"}}, []string{"a", "b", "c"}))
}

// isCI returns whether we might be running in a continuous integration environment. GitHub
// Actions and most other CI plaforms set the CI environment variable.
func isCI() bool {
	_, ok := os.LookupEnv("CI")
	return ok
}

// profileDuration sets the profile runtime to a shorter time period
// when running outside of CI. The logic for this is that very loaded
// systems, such as GH actions might take a long time to spawn processes.
// By increasing the runtime we reduce the chance of flaky test executions,
// but we shouldn't have to pay this price during local dev.
func profileDuration() time.Duration {
	if isCI() {
		return 20 * time.Second
	}
	return 5 * time.Second
}

// parsePrometheusMetricsEndpoint does some very light parsing of the metrics
// published in Prometheus.
func parsePrometheusMetricsEndpoint(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		splittedLine := strings.Split(line, " ")
		if len(splittedLine) < 2 {
			continue
		}
		key := splittedLine[0]
		value := splittedLine[1]
		result[key] = value
	}
	return result
}

// TestCPUProfilerWorks is the integration test for the CPU profiler. It
// uses an in-memory profile writer to be verify that the data we produce
// is correct.
func TestCPUProfilerWorks(t *testing.T) {
	defer goleak.VerifyNone(
		t,
		goleak.IgnoreTopFunction("github.com/baidubce/bce-sdk-go/util/log.NewLogger.func1"),
		goleak.IgnoreTopFunction("github.com/golang/glog.(*fileSink).flushDaemon"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)

	profileStore := NewTestProfileStore()
	tempDir := t.TempDir()
	logger := logger.NewLogger("error", logger.LogFormatLogfmt, "parca-agent-tests")
	profileDuration := profileDuration()
	level.Info(logger).Log("profileDuration", profileDuration)

	ctx, cancel := context.WithTimeout(context.Background(), profileDuration)
	defer cancel()

	profiler, reg, ofp := prepareProfiler(t, profileStore, logger, tempDir)
	t.Cleanup(func() {
		ofp.Close()
	})

	// Test unwinding without frame pointers.
	noFramePointersCmd := exec.Command("../../testdata/out/x86/basic-cpp-no-fp-with-debuginfo")
	err := noFramePointersCmd.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		noFramePointersCmd.Process.Kill()
	})
	dwarfUnwoundPid := noFramePointersCmd.Process.Pid

	// Test unwinding JIT without frame pointers in the AoT code.
	jitCmd := exec.Command("../../testdata/out/x86/basic-cpp-jit-no-fp")
	err = jitCmd.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		jitCmd.Process.Kill()
	})
	jitPid := jitCmd.Process.Pid

	// Test unwinding with frame pointers.
	framePointersCmd := exec.Command("../../testdata/out/x86/basic-go", "20000")
	err = framePointersCmd.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		framePointersCmd.Process.Kill()
	})
	fpUnwoundPid := framePointersCmd.Process.Pid

	// Now that all the processes are running, start profiling them.
	err = profiler.Run(ctx)
	require.Equal(t, err, context.DeadlineExceeded)
	require.True(t, len(profileStore.samples) > 0)

	t.Run("dwarf unwinding", func(t *testing.T) {
		sample := profileStore.SampleForProcess(dwarfUnwoundPid, false)
		require.NotNil(t, sample)

		// Test basic profile structure.
		require.True(t, sample.profile.DurationNanos < profileDuration.Nanoseconds())
		require.Equal(t, sample.profile.SampleType[0].Type, "samples")
		require.Equal(t, sample.profile.SampleType[0].Unit, "count")

		require.True(t, len(sample.profile.Sample) > 0)
		require.True(t, len(sample.profile.Location) > 0)
		require.True(t, len(sample.profile.Mapping) > 0)

		// Test expected metadata.
		require.Equal(t, string(sample.labels["comm"]), "basic-cpp-no-fp-with-debuginfo"[:15]) // comm is limited to 16 characters including NUL.
		require.True(t, strings.Contains(string(sample.labels["executable"]), "basic-cpp-no-fp-with-debuginfo"))
		require.True(t, strings.HasPrefix(string(sample.labels["compiler"]), "GCC"))
		require.NotEmpty(t, string(sample.labels["kernel_release"]))
		require.NotEmpty(t, string(sample.labels["cgroup_name"]))

		// Test symbolized stacks.
		aggregatedStacks := symbolizeProfile(t, sample.profile, true)
		require.True(t, len(aggregatedStacks) > 0)
		requireAnyStackContains(t, aggregatedStacks, []string{"top2()", "c2()", "b2()", "a2()", "main"})
		requireAnyStackContains(t, aggregatedStacks, []string{"top1()", "c1()", "b1()", "a1()", "main"})
	})

	t.Run("fp unwinding", func(t *testing.T) {
		sample := profileStore.SampleForProcess(fpUnwoundPid, false)
		require.NotNil(t, sample)

		// Test basic profile structure.
		require.True(t, sample.profile.DurationNanos < profileDuration.Nanoseconds())
		require.Equal(t, sample.profile.SampleType[0].Type, "samples")
		require.Equal(t, sample.profile.SampleType[0].Unit, "count")

		require.True(t, len(sample.profile.Sample) > 0)
		require.True(t, len(sample.profile.Location) > 0)
		require.True(t, len(sample.profile.Mapping) > 0)

		// Test expected metadata.
		require.Equal(t, string(sample.labels["comm"]), "basic-go")
		require.True(t, strings.Contains(string(sample.labels["executable"]), "basic-go"))
		require.True(t, strings.HasPrefix(string(sample.labels["compiler"]), "Go"))
		require.NotEmpty(t, string(sample.labels["kernel_release"]))
		require.NotEmpty(t, string(sample.labels["cgroup_name"]))

		// Test symbolized stacks.
		aggregatedStacks := symbolizeProfile(t, sample.profile, false)
		require.True(t, len(aggregatedStacks) > 0)
		requireAnyStackContains(t, aggregatedStacks, []string{"time.Now", "main.main"})
	})

	t.Run("mixed mode unwinding", func(t *testing.T) {
		sample := profileStore.SampleForProcess(jitPid, false)
		require.NotNil(t, sample)

		// Test basic profile structure.
		require.True(t, sample.profile.DurationNanos < profileDuration.Nanoseconds())
		require.Equal(t, sample.profile.SampleType[0].Type, "samples")
		require.Equal(t, sample.profile.SampleType[0].Unit, "count")

		require.True(t, len(sample.profile.Sample) > 0)
		require.True(t, len(sample.profile.Location) > 0)
		require.True(t, len(sample.profile.Mapping) > 0)

		// Test expected metadata.
		require.Equal(t, string(sample.labels["comm"]), "basic-cpp-jit-no-fp"[:15]) // comm is limited to 16 characters including NUL.
		require.True(t, strings.Contains(string(sample.labels["executable"]), "basic-cpp-jit-no-fp"))
		require.True(t, strings.HasPrefix(string(sample.labels["compiler"]), "GCC"))
		require.NotEmpty(t, string(sample.labels["kernel_release"]))
		require.NotEmpty(t, string(sample.labels["cgroup_name"]))

		// Test symbolized stacks.
		aggregatedStacks := symbolizeProfile(t, sample.profile, true)
		require.True(t, len(aggregatedStacks) > 0)
		requireAnyStackContains(t, aggregatedStacks, []string{"aot_top()", "aot2()", "aot1()", "aot()", "main"})

		// Test jitted stacks.
		// TODO(javierhonduco): Figure out why this consistently fails in CI.
		if !isCI() {
			jitStacks := jitProfile(t, sample.profile)
			requireAnyStackContains(t, jitStacks, []string{"jit_top", "jit_middle"})
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

		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr)) //nolint: noctx
		require.Nil(t, err)
		t.Cleanup(func() {
			resp.Body.Close()
		})

		body, err := io.ReadAll(resp.Body)
		require.Nil(t, err)

		metrics := parsePrometheusMetricsEndpoint(string(body))
		require.Greater(t, len(metrics), 0)

		// TODO: fix this assertion, all the BPF map metrics are zero but I am not sure why.
		// i, err := strconv.Atoi(metrics[`parca_agent_native_unwinder_success_total{unwinder="dwarf"}`])
		// require.Nil(t, err)
		// require.Greater(t, i, 0)
	})
}
