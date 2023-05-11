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

package cpu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/google/pprof/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/address"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/rlimit"
	"github.com/parca-dev/parca-agent/pkg/symbol"
	"github.com/parca-dev/parca-agent/pkg/vdso"
)

type Sample struct {
	labels  model.LabelSet
	profile *profile.Profile
}

type TestProfileWriter struct {
	samples []Sample
}

func NewTestProfileWriter() *TestProfileWriter {
	return &TestProfileWriter{samples: make([]Sample, 0)}
}

func (tpw *TestProfileWriter) Write(_ context.Context, labels model.LabelSet, profile *profile.Profile) error {
	tpw.samples = append(tpw.samples, Sample{
		labels:  labels,
		profile: profile,
	})
	return nil
}

// SampleForProcess returns the first or last matching sample for a given
// PID.
func (tpw *TestProfileWriter) SampleForProcess(pid int, last bool) *Sample {
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
func symbolizeProfile(t *testing.T, profile *profile.Profile, demangle bool) [][]string {
	t.Helper()

	symbolizer := NewLocalSymbolizer()
	demangler := NewLocalDemangler()

	aggregatedStacks := make([][]string, 0)
	for _, stack := range profile.Sample {
		aggregatedStack := make([]string, 0, len(stack.Location))
		for _, frame := range stack.Location {
			address := frame.Address
			file := frame.Mapping.File

			if file == "<unknown path>" {
				continue
			}

			funcName, err := symbolizer.Symbolize(file, address)
			require.Nil(t, err)

			if demangle {
				funcName, err = demangler.Demangle(funcName)
				require.Nil(t, err)
			}

			aggregatedStack = append(aggregatedStack, funcName)
		}
		aggregatedStacks = append(aggregatedStacks, aggregatedStack)
	}

	return aggregatedStacks
}

func anyStackEqual(aggregatedStacks [][]string, stack []string) bool {
	for _, aggregatedStack := range aggregatedStacks {
		if len(aggregatedStack) == len(stack) {
			equal := true
			for i := range aggregatedStack {
				if aggregatedStack[i] != stack[i] {
					equal = false
					break
				}
			}
			if equal {
				return true
			}
		}
	}
	return false
}

func prepareProfiler(t *testing.T, profileWriter profiler.ProfileWriter, logger log.Logger, tempDir string) (*CPU, *objectfile.Pool) {
	t.Helper()

	loopDuration := 1 * time.Second
	disableJit := true
	frequency := uint64(27)
	reg := prometheus.NewRegistry()
	pfs, err := procfs.NewDefaultFS()
	require.Nil(t, err)
	bpfProgramLoaded := make(chan bool, 1)
	normalizeAddresses := true
	memlockRlimit := uint64(4000000)

	curr, _, err := rlimit.Files()
	require.Nil(t, err)

	ofp := objectfile.NewPool(logger, reg, curr)

	vdsoCache, err := vdso.NewCache(ofp)
	require.Nil(t, err)

	dbginfo := debuginfo.NoopDebuginfoManager{}
	labelsManager := labels.NewManager(
		logger,
		reg,
		[]metadata.Provider{
			metadata.Compiler(logger, reg, ofp),
			metadata.Process(pfs),
			metadata.System(),
			metadata.PodHosts(),
		},
		[]*relabel.Config{},
		loopDuration,
	)

	profiler := NewCPUProfiler(
		logger,
		reg,
		process.NewInfoManager(
			logger,
			reg,
			process.NewMapManager(pfs, ofp),
			dbginfo,
			labelsManager,
			loopDuration,
		),
		address.NewNormalizer(logger, reg, normalizeAddresses),
		symbol.NewSymbolizer(
			log.With(logger, "component", "symbolizer"),
			perf.NewCache(logger),
			ksym.NewKsym(logger, reg, tempDir),
			vdsoCache,
			disableJit,
		),
		profileWriter,
		loopDuration,
		frequency,
		memlockRlimit,
		[]string{},
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

// TestCPUProfilerWorks is the integration test for the CPU profiler. It
// uses an in-memory profile writer to be verify that the data we produce
// is correct.
func TestCPUProfilerWorks(t *testing.T) {
	// Once this test is less flaky, we will enable it in CI.
	if os.Getenv("CI") != "" {
		t.Skip("Skipping integration tests to avoid flakiness in CI")
	}
	profileWriter := NewTestProfileWriter()
	profileDuration := 4 * time.Second
	tempDir := t.TempDir()
	logger := logger.NewLogger("error", logger.LogFormatLogfmt, "parca-agent-tests")

	ctx, cancel := context.WithTimeout(context.Background(), profileDuration)
	defer cancel()

	profiler, ofp := prepareProfiler(t, profileWriter, logger, tempDir)
	defer ofp.Close()

	// Test unwinding without frame pointers.
	noFramePointersCmd := exec.Command("../../../testdata/out/basic-cpp-no-fp-with-debuginfo")
	err := noFramePointersCmd.Start()
	require.Nil(t, err)
	defer noFramePointersCmd.Process.Kill()
	dwarfUnwoundPid := noFramePointersCmd.Process.Pid

	// Test unwinding with frame pointers.
	framePointersCmd := exec.Command("../../../testdata/out/basic-go", "20000")
	err = framePointersCmd.Start()
	require.Nil(t, err)
	defer framePointersCmd.Process.Kill()
	fpUnwoundPid := framePointersCmd.Process.Pid

	err = profiler.Run(ctx)
	require.Equal(t, err, context.DeadlineExceeded)

	require.True(t, len(profileWriter.samples) > 0)

	{
		sample := profileWriter.SampleForProcess(dwarfUnwoundPid, false)
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
		require.True(t, anyStackEqual(aggregatedStacks, []string{"top2()", "c2()", "b2()", "a2()", "main", "__libc_start_call_main", "__libc_start_main_alias_2"}))
		require.True(t, anyStackEqual(aggregatedStacks, []string{"top1()", "c1()", "b1()", "a1()", "main", "__libc_start_call_main", "__libc_start_main_alias_2"}))
	}

	{
		sample := profileWriter.SampleForProcess(fpUnwoundPid, false)
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
		require.True(t, anyStackEqual(aggregatedStacks, []string{"time.Now", "main.main", "runtime.main", "runtime.goexit.abi0"}))
	}
}

// The intent of these tests is to ensure that libbpfgo behaves the
// way we expect.
//
// We also use them to ensure that different kernel versions load our
// BPF program.
func SetUpBpfProgram(t *testing.T) (*bpf.Module, error) {
	t.Helper()
	logger := logger.NewLogger("error", logger.LogFormatLogfmt, "parca-cpu-test")

	memLock := uint64(1200 * 1024 * 1024) // ~1.2GiB
	m, _, err := loadBpfProgram(logger, prometheus.NewRegistry(), true, true, memLock)
	require.NoError(t, err)

	return m, err
}

func TestDeleteNonExistentKeyReturnsEnoent(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(stackCountsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Delete should fail as the key doesn't exist.
	err = bpfMap.DeleteKey(unsafe.Pointer(&stackID))
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOENT)
}

func TestDeleteExistentKey(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(stackCountsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Insert some element that will be later deleted.
	value := []byte{'a'}
	err = bpfMap.Update(unsafe.Pointer(&stackID), unsafe.Pointer(&value[0]))
	require.NoError(t, err)

	// Delete should work.
	err = bpfMap.DeleteKey(unsafe.Pointer(&stackID))
	require.NoError(t, err)
}

func hasBatchOperations(t *testing.T) bool {
	t.Helper()

	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(stackCountsMapName)
	require.NoError(t, err)

	keys := make([]stackCountKey, bpfMap.GetMaxEntries())
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := bpfMap.GetMaxEntries()
	_, err = bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)

	return err == nil
}

func TestGetValueAndDeleteBatchWithEmptyMap(t *testing.T) {
	if !hasBatchOperations(t) {
		t.Skip("Skipping testing of batched operations as they aren't supported")
	}

	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(stackCountsMapName)
	require.NoError(t, err)

	keys := make([]stackCountKey, bpfMap.GetMaxEntries())
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := bpfMap.GetMaxEntries()
	values, err := bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)
	require.NoError(t, err)
	require.Equal(t, 0, len(values))
}

func TestGetValueAndDeleteBatchFewerElementsThanCount(t *testing.T) {
	if !hasBatchOperations(t) {
		t.Skip("Skipping testing of batched operations as they aren't supported")
	}

	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(stackCountsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Insert some element that will be later deleted.
	value := []byte{'a'}
	err = bpfMap.Update(unsafe.Pointer(&stackID), unsafe.Pointer(&value[0]))
	require.NoError(t, err)

	// Request more elements than we have, this should return and delete everything.
	keys := make([]stackCountKey, bpfMap.GetMaxEntries())
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := bpfMap.GetMaxEntries()
	values, err := bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)
	require.NoError(t, err)
	require.Equal(t, 1, len(values))
}

func TestGetValueAndDeleteBatchExactElements(t *testing.T) {
	if !hasBatchOperations(t) {
		t.Skip("Skipping testing of batched operations as they aren't supported")
	}

	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(stackCountsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Insert some element that will be later deleted.
	value := []byte{'a'}
	err = bpfMap.Update(unsafe.Pointer(&stackID), unsafe.Pointer(&value[0]))
	require.NoError(t, err)

	// Request exactly the elements we have.
	keys := make([]stackCountKey, 1)
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := uint32(1)
	values, err := bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)
	require.NoError(t, err)
	require.Equal(t, 1, len(values))
}
