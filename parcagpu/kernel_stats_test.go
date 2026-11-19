// Copyright 2026 The Parca Authors
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

package parcagpu

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
)

// kernelStatsResourcer names each process by PID and drops PIDs in drop.
type kernelStatsResourcer struct{ drop map[uint32]bool }

func (r kernelStatsResourcer) PutResource(pid uint32, attrs pcommon.Map) bool {
	if r.drop[pid] {
		return false
	}
	attrs.PutInt("process.pid", int64(pid))
	return true
}

func statsEvent(pid, seq, dev, stream uint32, execs, ns uint64) *gpu.CuptiKernelStatsEvent {
	return &gpu.CuptiKernelStatsEvent{
		EventType:  gpu.EventTypeKernelStats,
		Pid:        pid,
		Seq:        seq,
		DeviceID:   dev,
		StreamID:   stream,
		Executions: execs,
		TotalNs:    ns,
	}
}

type point struct {
	execs int64
	secs  float64
}

// produce renders p and returns, per PID, the points keyed by kernel name and
// stream, checking that both metrics carry the same series.
func produce(t *testing.T, p *KernelStatsProducer) map[int64]map[string]point {
	t.Helper()
	rms := pmetric.NewResourceMetricsSlice()
	require.NoError(t, p.Produce(pmetric.NewMetricSlice(), rms))

	out := map[int64]map[string]point{}
	for i := 0; i < rms.Len(); i++ {
		rm := rms.At(i)
		pid, ok := rm.Resource().Attributes().Get("process.pid")
		require.True(t, ok)
		sm := rm.ScopeMetrics().At(0)
		require.Equal(t, KernelStatsScopeName, sm.Scope().Name())
		require.Equal(t, 2, sm.Metrics().Len())

		execs, dur := sm.Metrics().At(0), sm.Metrics().At(1)
		require.Equal(t, metricKernelExecutions, execs.Name())
		require.Equal(t, metricKernelDuration, dur.Name())
		require.Equal(t, "s", dur.Unit())
		for _, m := range []pmetric.Metric{execs, dur} {
			require.True(t, m.Sum().IsMonotonic())
			require.Equal(t, pmetric.AggregationTemporalityCumulative, m.Sum().AggregationTemporality())
		}

		pts := map[string]point{}
		for j := 0; j < execs.Sum().DataPoints().Len(); j++ {
			e, d := execs.Sum().DataPoints().At(j), dur.Sum().DataPoints().At(j)
			require.Equal(t, e.Attributes().AsRaw(), d.Attributes().AsRaw())
			name, _ := e.Attributes().Get(attrKernelName)
			stream, _ := e.Attributes().Get(attrStreamID)
			pts[name.Str()+"/"+stream.AsString()] = point{e.IntValue(), d.DoubleValue()}
		}
		out[pid.Int()] = pts
	}
	return out
}

func TestKernelStatsProducerAccumulates(t *testing.T) {
	p := NewKernelStatsProducer(kernelStatsResourcer{})

	p.AddKernelStats(statsEvent(10, 0, 0, 13, 100, 2e9), "kernelA")
	p.AddKernelStats(statsEvent(10, 0, 0, 14, 5, 5e8), "kernelB")
	// Same firing split across probe calls, then the next firing.
	p.AddKernelStats(statsEvent(10, 0, 0, 13, 0, 0), "kernelC")
	p.AddKernelStats(statsEvent(10, 1, 0, 13, 50, 1e9), "kernelA")
	p.AddKernelStats(statsEvent(20, 7, 1, 3, 1, 1e6), "kernelA")

	got := produce(t, p)
	require.Equal(t, map[int64]map[string]point{
		10: {
			"kernelA/13": {150, 3},
			"kernelB/14": {5, 0.5},
			"kernelC/13": {0, 0},
		},
		20: {"kernelA/3": {1, 0.001}},
	}, got)
	require.Zero(t, p.LostFirings())

	// Sums stay cumulative across Produce calls.
	p.AddKernelStats(statsEvent(10, 2, 0, 13, 1, 0), "kernelA")
	require.Equal(t, int64(151), produce(t, p)[10]["kernelA/13"].execs)
}

func TestKernelStatsProducerLostFirings(t *testing.T) {
	p := NewKernelStatsProducer(kernelStatsResourcer{})
	p.AddKernelStats(statsEvent(10, 3, 0, 1, 1, 1), "k")
	p.AddKernelStats(statsEvent(10, 6, 0, 1, 1, 1), "k") // 4 and 5 missing
	require.Equal(t, uint64(2), p.LostFirings())
	require.Zero(t, p.LostFirings())

	// A new process reusing the PID starts over at 0; nothing was lost.
	p.AddKernelStats(statsEvent(10, 0, 0, 1, 1, 1), "k")
	require.Zero(t, p.LostFirings())
}

func TestKernelStatsProducerDropsAndExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := NewKernelStatsProducer(kernelStatsResourcer{drop: map[uint32]bool{20: true}})
	p.now = func() time.Time { return now }

	p.AddKernelStats(statsEvent(10, 0, 0, 1, 1, 1), "k")
	p.AddKernelStats(statsEvent(20, 0, 0, 1, 1, 1), "k")
	got := produce(t, p)
	require.Contains(t, got, int64(10))
	require.NotContains(t, got, int64(20), "relabel-dropped process must not be exported")

	now = now.Add(kernelStatsIdleExpiry + time.Second)
	p.expire()
	require.Empty(t, produce(t, p))
}
