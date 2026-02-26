package reporter

import (
	"fmt"
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	Chinese  string = "Go（又稱Golang[4]）是Google開發的一种静态强类型、編譯型、并发型，并具有垃圾回收功能的编程语言。"
	Chinese2 string = "Linux是一种自由和开放源码的类Unix操作系统。"
)

func TestMaybeFixTruncation(t *testing.T) {
	for _, test := range []struct {
		s      string
		result string
		ok     bool
	}{
		{"ASCII string", "ASCII string", true},
		// truncated, but too early -- can't be valid utf8
		{Chinese[0:4], "", false},
		// truncated at the limit, in the middle of a rune
		{Chinese[0:48], Chinese[0:47], true},
		// Too long string that happened to be
		// truncated on a rune boundary
		{Chinese2[0:48], Chinese2[0:48], true},
		// Too long string but valid UTF-8 --
		// the function should pass it through unscathed
		// (it is not responsible for doing its own truncation)
		{Chinese2, Chinese2, true},
	} {
		result, ok := maybeFixTruncation(test.s, 48)
		require.Equal(t, test.result, result)
		require.Equal(t, test.ok, ok)
	}
}

func newTestReporter(t *testing.T) *ParcaReporter {
	t.Helper()
	return newTestReporterWithFlags(t, false, false, false)
}

func newTestReporterWithFlags(t *testing.T, disableCPU, disableThreadID, disableThreadComm bool) *ParcaReporter {
	t.Helper()

	labels, err := lru.NewSynced[libpf.PID, labelRetrievalResult](1024, libpf.PID.Hash32)
	require.NoError(t, err)
	labels.SetLifetime(10 * time.Minute)

	return &ParcaReporter{
		labels:                 labels,
		nodeName:               "test-node",
		disableCPULabel:        disableCPU,
		disableThreadIDLabel:   disableThreadID,
		disableThreadCommLabel: disableThreadComm,
	}
}

func TestLabelsForTID_CPUCacheMismatch(t *testing.T) {
	r := newTestReporter(t)

	tid := libpf.PID(1234)
	pid := libpf.PID(1000)

	// First call: TID 1234 on CPU 1 — cache miss, labels built fresh.
	result1 := r.labelsForTID(tid, pid, "myprocess", 1, nil)
	require.True(t, result1.keep)
	require.Equal(t, "1", result1.labels.Get("cpu"),
		"first call should set cpu=1")

	// Second call: same TID on CPU 3 — should return cpu=3, not stale cpu=1.
	result2 := r.labelsForTID(tid, pid, "myprocess", 3, nil)
	require.True(t, result2.keep)
	require.Equal(t, "3", result2.labels.Get("cpu"),
		"same TID on different CPU must return the actual cpu value")
}

func TestLabelsForTID_ThreadMigrationPattern(t *testing.T) {
	// Simulates a realistic thread migration scenario:
	// A thread is profiled across multiple ticks, migrating between CPUs.
	r := newTestReporter(t)

	tid := libpf.PID(4243)
	pid := libpf.PID(4140)

	cpuSequence := []int{0, 1, 0, 3, 2, 1, 3, 0}

	for i, cpu := range cpuSequence {
		result := r.labelsForTID(tid, pid, "myprocess", cpu, nil)
		require.Equal(t, fmt.Sprint(cpu), result.labels.Get("cpu"),
			"tick %d: thread on cpu %d must get cpu=%d in labels", i, cpu, cpu)
	}
}

func TestLabelsForTID_DisableFlags(t *testing.T) {
	tid := libpf.PID(1234)
	pid := libpf.PID(1000)

	t.Run("all enabled", func(t *testing.T) {
		r := newTestReporterWithFlags(t, false, false, false)
		res := r.labelsForTID(tid, pid, "myprocess", 2, nil)
		require.True(t, res.keep)
		require.Equal(t, "2", res.labels.Get("cpu"))
		require.Equal(t, "1234", res.labels.Get("thread_id"))
		require.Equal(t, "myprocess", res.labels.Get("thread_name"))
	})

	t.Run("cpu disabled", func(t *testing.T) {
		r := newTestReporterWithFlags(t, true, false, false)
		res := r.labelsForTID(tid, pid, "myprocess", 2, nil)
		require.True(t, res.keep)
		require.Equal(t, "", res.labels.Get("cpu"))
		require.Equal(t, "1234", res.labels.Get("thread_id"))
		require.Equal(t, "myprocess", res.labels.Get("thread_name"))
	})

	t.Run("thread_id disabled", func(t *testing.T) {
		r := newTestReporterWithFlags(t, false, true, false)
		res := r.labelsForTID(tid, pid, "myprocess", 2, nil)
		require.True(t, res.keep)
		require.Equal(t, "2", res.labels.Get("cpu"))
		require.Equal(t, "", res.labels.Get("thread_id"))
		require.Equal(t, "myprocess", res.labels.Get("thread_name"))
	})

	t.Run("thread_name disabled", func(t *testing.T) {
		r := newTestReporterWithFlags(t, false, false, true)
		res := r.labelsForTID(tid, pid, "myprocess", 2, nil)
		require.True(t, res.keep)
		require.Equal(t, "2", res.labels.Get("cpu"))
		require.Equal(t, "1234", res.labels.Get("thread_id"))
		require.Equal(t, "", res.labels.Get("thread_name"))
	})

	t.Run("all disabled", func(t *testing.T) {
		r := newTestReporterWithFlags(t, true, true, true)
		res := r.labelsForTID(tid, pid, "myprocess", 2, nil)
		require.True(t, res.keep)
		require.Equal(t, "", res.labels.Get("cpu"))
		require.Equal(t, "", res.labels.Get("thread_id"))
		require.Equal(t, "", res.labels.Get("thread_name"))
		// node label should still be present
		require.Equal(t, "test-node", res.labels.Get("node"))
	})
}
