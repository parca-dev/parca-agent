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
	"cmp"
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// KernelStatsScopeName is the OTLP instrumentation scope of the kernel
// execution metrics.
const KernelStatsScopeName = "parca.cuda_kernel_stats"

const (
	metricKernelExecutions = "cuda.kernel.executions"
	metricKernelDuration   = "cuda.kernel.duration"

	attrHwID       = "hw.id"
	attrDeviceID   = "cuda.device.id"
	attrStreamID   = "cuda.stream.id"
	attrKernelName = "cuda.kernel.name"

	// kernelStatsIdleExpiry drops a process's series once parcagpu has sent
	// nothing for it this long. parcagpu fires at most once a second while
	// kernels run, so this only drops processes that exited or went idle.
	kernelStatsIdleExpiry = 10 * time.Minute

	// kernelStatsDeviceWait is how long a new series waits for its device's
	// UUID before it is exported without hw.id. parcagpu reports the mapping
	// when it creates a context on the device and replays it with the other
	// metadata (every 30s by default), so this covers a late attach; builds
	// without the device_info probe never report it.
	kernelStatsDeviceWait = time.Minute
)

// KernelStatsSink receives parcagpu kernel_stats records from the
// cupti_events reader.
type KernelStatsSink interface {
	AddKernelStats(ev *gpu.CuptiKernelStatsEvent, kernelName string)
}

type kernelSeriesKey struct {
	device uint32
	stream uint32
	name   string
}

type kernelSeries struct {
	executions uint64
	totalNs    uint64
	start      pcommon.Timestamp
	updated    pcommon.Timestamp

	// hwID is the GPU's UUID, as NVML metrics carry it in hw.id, or "" if
	// it never arrived. It is settled once (hwIDSettled), before the
	// series is first exported, so the series' attributes never change.
	hwID        string
	hwIDSettled bool
	created     time.Time
}

type kernelStatsProcess struct {
	series  map[kernelSeriesKey]*kernelSeries
	lastSeq uint32
	seen    bool
	updated time.Time
}

// KernelStatsProducer turns parcagpu's kernel_stats deltas into cumulative
// OTLP sums per (process, CUDA device, stream, kernel), each with the GPU's
// UUID as hw.id, the key NVML's GPU metrics use, when parcagpu reported it:
//
//   - cuda.kernel.executions: kernel executions, graph kernel nodes included
//   - cuda.kernel.duration:   summed kernel run time, in seconds
//
// parcagpu counts every kernel before its launch rate limiter, so unlike the
// gpu_kernel_time profile these are totals, not samples. They cover only the
// time a profiler was attached to the process. Each process is a resource of
// its own, rendered like its profiles' resource.
type KernelStatsProducer struct {
	resourcer gpumetrics.ProcessResourcer
	now       func() time.Time
	// deviceUUID returns the UUID of CUDA ordinal dev in process pid.
	deviceUUID func(pid, dev uint32) (string, bool)

	mu    sync.Mutex
	procs map[uint32]*kernelStatsProcess
	lost  uint64 // firings missed, from gaps in the per-process sequence
}

// NewKernelStatsProducer returns a producer that resolves process resources
// with resourcer.
func NewKernelStatsProducer(resourcer gpumetrics.ProcessResourcer) *KernelStatsProducer {
	return &KernelStatsProducer{
		resourcer:  resourcer,
		now:        time.Now,
		deviceUUID: loadDeviceUUID,
		procs:      map[uint32]*kernelStatsProcess{},
	}
}

func loadDeviceUUID(pid, dev uint32) (string, bool) {
	info, ok := gpu.LoadDeviceInfo(pid, dev)
	if !ok {
		return "", false
	}
	return info.UUIDString(), true
}

// AddKernelStats adds one kernel_stats delta.
func (p *KernelStatsProducer) AddKernelStats(ev *gpu.CuptiKernelStatsEvent, kernelName string) {
	now := p.now()
	ts := pcommon.NewTimestampFromTime(now)

	p.mu.Lock()
	defer p.mu.Unlock()

	proc := p.procs[ev.Pid]
	if proc == nil {
		proc = &kernelStatsProcess{series: map[kernelSeriesKey]*kernelSeries{}}
		p.procs[ev.Pid] = proc
	}
	// A firing with more entries than one probe call holds repeats its
	// sequence number, so only a jump forward means a firing went missing.
	// A smaller number means the PID was reused by a new process.
	if proc.seen && ev.Seq > proc.lastSeq+1 {
		p.lost += uint64(ev.Seq - proc.lastSeq - 1)
	}
	proc.lastSeq, proc.seen = ev.Seq, true
	proc.updated = now

	key := kernelSeriesKey{device: ev.DeviceID, stream: ev.StreamID, name: kernelName}
	s := proc.series[key]
	if s == nil {
		s = &kernelSeries{start: ts, created: now}
		proc.series[key] = s
	}
	s.executions += ev.Executions
	s.totalNs += ev.TotalNs
	s.updated = ts
}

// LostFirings returns and resets the number of kernel_stats firings detected
// as missing since the last call.
func (p *KernelStatsProducer) LostFirings() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.lost
	p.lost = 0
	return n
}

// Collect only expires idle processes; records arrive through
// AddKernelStats.
func (p *KernelStatsProducer) Collect(ctx context.Context) error {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			p.expire()
		}
	}
}

func (p *KernelStatsProducer) expire() {
	cutoff := p.now().Add(-kernelStatsIdleExpiry)
	p.mu.Lock()
	defer p.mu.Unlock()
	maps.DeleteFunc(p.procs, func(_ uint32, proc *kernelStatsProcess) bool {
		return proc.updated.Before(cutoff)
	})
}

type kernelSeriesSnapshot struct {
	key kernelSeriesKey
	kernelSeries
}

// settleHwID settles s's hw.id if it can, and reports whether it is
// settled. Called with p.mu held.
func (p *KernelStatsProducer) settleHwID(pid uint32, k kernelSeriesKey, s *kernelSeries, now time.Time) bool {
	if s.hwIDSettled {
		return true
	}
	if uuid, ok := p.deviceUUID(pid, k.device); ok {
		s.hwID, s.hwIDSettled = uuid, true
	} else if now.Sub(s.created) >= kernelStatsDeviceWait {
		s.hwIDSettled = true
	}
	return s.hwIDSettled
}

// Produce renders the cumulative sums of every live process. A series is
// held back until its hw.id is settled (see kernelStatsDeviceWait).
func (p *KernelStatsProducer) Produce(_ pmetric.MetricSlice, resources pmetric.ResourceMetricsSlice) error {
	now := p.now()
	p.mu.Lock()
	snap := make(map[uint32][]kernelSeriesSnapshot, len(p.procs))
	for pid, proc := range p.procs {
		ss := make([]kernelSeriesSnapshot, 0, len(proc.series))
		for k, s := range proc.series {
			if p.settleHwID(pid, k, s, now) {
				ss = append(ss, kernelSeriesSnapshot{key: k, kernelSeries: *s})
			}
		}
		if len(ss) > 0 {
			snap[pid] = ss
		}
	}
	p.mu.Unlock()

	for _, pid := range slices.Sorted(maps.Keys(snap)) {
		series := snap[pid]
		slices.SortFunc(series, func(a, b kernelSeriesSnapshot) int {
			return cmp.Or(cmp.Compare(a.key.device, b.key.device),
				cmp.Compare(a.key.stream, b.key.stream),
				cmp.Compare(a.key.name, b.key.name))
		})

		attrs := pcommon.NewMap()
		if !p.resourcer.PutResource(pid, attrs) {
			continue
		}
		rm := resources.AppendEmpty()
		rm.SetSchemaUrl(processlabels.SchemaURL)
		attrs.MoveTo(rm.Resource().Attributes())
		sm := rm.ScopeMetrics().AppendEmpty()
		sm.SetSchemaUrl(processlabels.SchemaURL)
		sm.Scope().SetName(KernelStatsScopeName)

		execs := newCumulativeSum(sm.Metrics(), metricKernelExecutions, "{execution}",
			"CUDA kernel executions, graph kernel nodes included, while profiled.")
		dur := newCumulativeSum(sm.Metrics(), metricKernelDuration, "s",
			"Summed CUDA kernel run time while profiled.")
		for _, s := range series {
			dp := execs.DataPoints().AppendEmpty()
			putKernelAttrs(dp.Attributes(), s)
			dp.SetStartTimestamp(s.start)
			dp.SetTimestamp(s.updated)
			dp.SetIntValue(int64(s.executions))

			dp = dur.DataPoints().AppendEmpty()
			putKernelAttrs(dp.Attributes(), s)
			dp.SetStartTimestamp(s.start)
			dp.SetTimestamp(s.updated)
			dp.SetDoubleValue(float64(s.totalNs) / 1e9)
		}
	}
	return nil
}

func newCumulativeSum(ms pmetric.MetricSlice, name, unit, desc string) pmetric.Sum {
	m := ms.AppendEmpty()
	m.SetName(name)
	m.SetUnit(unit)
	m.SetDescription(desc)
	sum := m.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	return sum
}

func putKernelAttrs(attrs pcommon.Map, s kernelSeriesSnapshot) {
	if s.hwID != "" {
		attrs.PutStr(attrHwID, s.hwID)
	}
	attrs.PutInt(attrDeviceID, int64(s.key.device))
	attrs.PutInt(attrStreamID, int64(s.key.stream))
	attrs.PutStr(attrKernelName, s.key.name)
}
