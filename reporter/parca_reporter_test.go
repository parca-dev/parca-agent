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

func newTestReporter(t *testing.T, relabelConfigs []*relabel.Config) *ParcaReporter {
	t.Helper()

	labels, err := lru.NewSynced[tidCPUKey, labelRetrievalResult](1024, tidCPUKey.Hash32)
	require.NoError(t, err)
	labels.SetLifetime(10 * time.Minute)

	return &ParcaReporter{
		labels:         labels,
		nodeName:       "test-node",
		relabelConfigs: relabelConfigs,
	}
}

func cpuRelabelConfig() []*relabel.Config {
	return []*relabel.Config{
		{
			SourceLabels: model.LabelNames{"__meta_cpu"},
			TargetLabel:  "cpu",
			Action:       relabel.Replace,
			Regex:        relabel.MustNewRegexp("(.*)"),
			Replacement:  "$1",
			Separator:    ";",
		},
	}
}

func TestLabelsForTID_CPUCacheMismatch(t *testing.T) {
	r := newTestReporter(t, cpuRelabelConfig())

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
	r := newTestReporter(t, cpuRelabelConfig())

	tid := libpf.PID(4243)
	pid := libpf.PID(4140)

	cpuSequence := []int{0, 1, 0, 3, 2, 1, 3, 0}

	for i, cpu := range cpuSequence {
		result := r.labelsForTID(tid, pid, "myprocess", cpu, nil)
		require.Equal(t, fmt.Sprint(cpu), result.labels.Get("cpu"),
			"tick %d: thread on cpu %d must get cpu=%d in labels", i, cpu, cpu)
	}
}
