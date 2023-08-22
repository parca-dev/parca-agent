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
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	pprofprofile "github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

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

			if file == "jit" || strings.HasPrefix(file, "[") {
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

func prepareProfiler(t *testing.T, profileStore profiler.ProfileStore, logger log.Logger, tempDir string) (*cpu.CPU, *objectfile.Pool) {
	t.Helper()

	loopDuration := 1 * time.Second
	disableJit := true
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
		loopDuration,
		frequency,
		250,
		100,
		8,
		memlockRlimit,
		[]string{},
		false,
		false,
		true,
		bpfProgramLoaded,
	)

	// Wait for the BPF program to be loaded.
	for len(bpfProgramLoaded) > 0 {
		<-bpfProgramLoaded
	}

	return profiler, ofp
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

// TestCPUProfilerWorks is the integration test for the CPU profiler. It
// uses an in-memory profile writer to be verify that the data we produce
// is correct.
func TestCPUProfilerWorks(t *testing.T) {
	profileStore := NewTestProfileStore()
	profileDuration := 20 * time.Second
	tempDir := t.TempDir()
	logger := logger.NewLogger("error", logger.LogFormatLogfmt, "parca-agent-tests")

	ctx, cancel := context.WithTimeout(context.Background(), profileDuration)
	defer cancel()

	profiler, ofp := prepareProfiler(t, profileStore, logger, tempDir)
	defer ofp.Close()

	// Test unwinding without frame pointers.
	noFramePointersCmd := exec.Command("../../testdata/out/x86/basic-cpp-no-fp-with-debuginfo")
	err := noFramePointersCmd.Start()
	require.NoError(t, err)
	defer noFramePointersCmd.Process.Kill()
	dwarfUnwoundPid := noFramePointersCmd.Process.Pid

	// Test unwinding with frame pointers.
	framePointersCmd := exec.Command("../../testdata/out/x86/basic-go", "20000")
	err = framePointersCmd.Start()
	require.NoError(t, err)
	defer framePointersCmd.Process.Kill()
	fpUnwoundPid := framePointersCmd.Process.Pid

	err = profiler.Run(ctx)
	require.Equal(t, err, context.DeadlineExceeded)

	require.True(t, len(profileStore.samples) > 0)

	{
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
	}

	{
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
	}
}
