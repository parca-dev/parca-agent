package reporter

import (
	"fmt"
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// dropAllRelabelConfig returns a relabel config that drops every process, by
// matching the node label every process carries.
func dropAllRelabelConfig(t *testing.T) []*relabel.Config {
	t.Helper()
	re, err := relabel.NewRegexp(".*")
	require.NoError(t, err)
	return []*relabel.Config{{
		Action:       relabel.Drop,
		SourceLabels: model.LabelNames{"node"},
		Regex:        re,
	}}
}

func newTestLabeler(t *testing.T) *processLabeler {
	t.Helper()
	return newTestLabelerWithFlags(t, false, false, false)
}

func newTestLabelerWithFlags(t *testing.T, disableCPU, disableThreadID, disableThreadComm bool) *processLabeler {
	t.Helper()

	lbls, err := lru.NewSynced[libpf.PID, labelRetrievalResult](1024, libpf.PID.Hash32)
	require.NoError(t, err)
	lbls.SetLifetime(10 * time.Minute)

	return &processLabeler{
		labels:                 lbls,
		nodeName:               "test-node",
		disableCPULabel:        disableCPU,
		disableThreadIDLabel:   disableThreadID,
		disableThreadCommLabel: disableThreadComm,
	}
}

func TestLabelsForTID_CPUCacheMismatch(t *testing.T) {
	l := newTestLabeler(t)

	tid := libpf.PID(1234)
	pid := libpf.PID(1000)

	// First call: TID 1234 on CPU 1 — cache miss, labels built fresh.
	result1 := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 1, support.TraceOriginSampling, nil)
	require.True(t, result1.keep)
	require.Equal(t, "1", result1.get("cpu"),
		"first call should set cpu=1")

	// Second call: same TID on CPU 3 — should return cpu=3, not stale cpu=1.
	result2 := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 3, support.TraceOriginSampling, nil)
	require.True(t, result2.keep)
	require.Equal(t, "3", result2.get("cpu"),
		"same TID on different CPU must return the actual cpu value")
}

func TestLabelsForTID_ThreadMigrationPattern(t *testing.T) {
	// Simulates a realistic thread migration scenario:
	// A thread is profiled across multiple ticks, migrating between CPUs.
	l := newTestLabeler(t)

	tid := libpf.PID(4243)
	pid := libpf.PID(4140)

	cpuSequence := []uint32{0, 1, 0, 3, 2, 1, 3, 0}

	for i, cpu := range cpuSequence {
		result := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), cpu, support.TraceOriginSampling, nil)
		require.Equal(t, fmt.Sprint(cpu), result.get("cpu"),
			"tick %d: thread on cpu %d must get cpu=%d in labels", i, cpu, cpu)
	}
}

func TestLabelsForTID_DisableFlags(t *testing.T) {
	tid := libpf.PID(1234)
	pid := libpf.PID(1000)

	t.Run("all enabled", func(t *testing.T) {
		l := newTestLabelerWithFlags(t, false, false, false)
		res := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
		require.True(t, res.keep)
		require.Equal(t, "2", res.get("cpu"))
		require.Equal(t, "1234", res.get("thread_id"))
		require.Equal(t, "myprocess", res.get("thread_name"))
	})

	t.Run("cpu disabled", func(t *testing.T) {
		l := newTestLabelerWithFlags(t, true, false, false)
		res := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
		require.True(t, res.keep)
		require.Equal(t, "", res.get("cpu"))
		require.Equal(t, "1234", res.get("thread_id"))
		require.Equal(t, "myprocess", res.get("thread_name"))
	})

	t.Run("thread_id disabled", func(t *testing.T) {
		l := newTestLabelerWithFlags(t, false, true, false)
		res := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
		require.True(t, res.keep)
		require.Equal(t, "2", res.get("cpu"))
		require.Equal(t, "", res.get("thread_id"))
		require.Equal(t, "myprocess", res.get("thread_name"))
	})

	t.Run("thread_name disabled", func(t *testing.T) {
		l := newTestLabelerWithFlags(t, false, false, true)
		res := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
		require.True(t, res.keep)
		require.Equal(t, "2", res.get("cpu"))
		require.Equal(t, "1234", res.get("thread_id"))
		require.Equal(t, "", res.get("thread_name"))
	})

	t.Run("all disabled", func(t *testing.T) {
		l := newTestLabelerWithFlags(t, true, true, true)
		res := l.labelsForTID(tid, pid, libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
		require.True(t, res.keep)
		require.Equal(t, "", res.get("cpu"))
		require.Equal(t, "", res.get("thread_id"))
		require.Equal(t, "", res.get("thread_name"))
		// node label should still be present
		require.Equal(t, "test-node", res.get("node"))
	})
}

// TestLabelsForTID_ResourceSampleSplit pins the boundary the OTLP backend
// depends on: process-invariant labels must land in `resource` and per-sample
// patches in `sample`. Getting this wrong does not fail the arrow backends --
// they flatten both -- so only this test catches it.
func TestLabelsForTID_ResourceSampleSplit(t *testing.T) {
	l := newTestLabeler(t)

	res := l.labelsForTID(libpf.PID(1234), libpf.PID(1000),
		libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
	require.True(t, res.keep)

	require.Equal(t, "test-node", res.resource.Get("node"),
		"node is constant for the process and belongs on the resource")
	require.Equal(t, "", res.sample.Get("node"),
		"node must not be duplicated onto every sample")

	for _, name := range perSampleLabelNames {
		require.NotEmpty(t, res.sample.Get(name),
			"%s is a per-sample patch and belongs on the sample", name)
		require.Empty(t, res.resource.Get(name),
			"%s must not be on the resource", name)
	}
}

// TestLabelsForTID_DroppedProcessHasNoLabels asserts a relabel drop short
// circuits before the per-sample patch work.
func TestLabelsForTID_DroppedProcessHasNoLabels(t *testing.T) {
	l := newTestLabeler(t)
	l.relabelConfigs = dropAllRelabelConfig(t)

	res := l.labelsForTID(libpf.PID(1234), libpf.PID(1000),
		libpf.NewCommFromString("myprocess"), 2, support.TraceOriginSampling, nil)
	require.False(t, res.keep, "relabeling must drop this process")
	require.Empty(t, res.sample, "a dropped process must not accrue sample labels")
}
