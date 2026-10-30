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
	"context"
	"fmt"
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"

	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/reporter/metadata"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

const testPID = 100

type fakeResourcer struct{ drop map[uint32]bool }

func (r fakeResourcer) PutResource(pid uint32, attrs pcommon.Map) bool {
	if r.drop[pid] {
		return false
	}
	attrs.PutInt("process.pid", int64(pid))
	attrs.PutStr("service.name", "trtllm")
	return true
}

// nvtxHarness drives an NvtxTracer synchronously with a fake clock.
type nvtxHarness struct {
	t     *testing.T
	tr    *NvtxTracer
	now   time.Time
	alive map[uint32]bool
	spans []ptrace.Span
	res   []pcommon.Map
	marks []plog.LogRecord
	mres  []pcommon.Map
}

func newHarness(t *testing.T, cfg NvtxTracerConfig) *nvtxHarness {
	h := &nvtxHarness{
		t:     t,
		now:   time.Unix(1_800_000_000, 0),
		alive: map[uint32]bool{testPID: true},
	}
	h.tr = NewNvtxTracer(cfg, fakeResourcer{}, func(_ context.Context, td ptrace.Traces) error {
		for i := 0; i < td.ResourceSpans().Len(); i++ {
			rs := td.ResourceSpans().At(i)
			ss := rs.ScopeSpans().At(0)
			assert.Equal(t, NvtxScope, ss.Scope().Name())
			for j := 0; j < ss.Spans().Len(); j++ {
				h.spans = append(h.spans, ss.Spans().At(j))
				h.res = append(h.res, rs.Resource().Attributes())
			}
		}
		return nil
	}, func(_ context.Context, ld plog.Logs) error {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			sl := rl.ScopeLogs().At(0)
			assert.Equal(t, NvtxScope, sl.Scope().Name())
			for j := 0; j < sl.LogRecords().Len(); j++ {
				h.marks = append(h.marks, sl.LogRecords().At(j))
				h.mres = append(h.mres, rl.Resource().Attributes())
			}
		}
		return nil
	})
	h.tr.now = func() time.Time { return h.now }
	h.tr.procAlive = func(pid uint32) bool { return h.alive[pid] }
	return h
}

// ev feeds one event at the harness clock plus offset ms.
func (h *nvtxHarness) ev(tid uint32, kind samples.NvtxKind, domain uint32, rangeID uint64, msg string, atMs int64) {
	h.tr.handle(nvtxInput{ev: samples.NvtxEvent{
		TimeUnixNano: h.now.UnixNano() + atMs*int64(time.Millisecond),
		PID:          testPID,
		TID:          tid,
		DeviceID:     math.MaxUint32,
		DomainID:     domain,
		Kind:         kind,
		RangeID:      rangeID,
		Message:      msg,
	}})
}

func (h *nvtxHarness) name(kind samples.NvtxResourceKind, id uint64, name string) {
	h.tr.handle(nvtxInput{name: &samples.NvtxResourceNameEvent{PID: testPID, Kind: kind, ID: id, Name: name}})
}

func (h *nvtxHarness) flush() { h.tr.flush(context.Background(), false) }

func (h *nvtxHarness) span(name string) ptrace.Span {
	for _, s := range h.spans {
		if s.Name() == name {
			return s
		}
	}
	h.t.Fatalf("no span %q in %d spans", name, len(h.spans))
	return ptrace.Span{}
}

func attr(s ptrace.Span, key string) any {
	v, ok := s.Attributes().Get(key)
	if !ok {
		return nil
	}
	return v.AsRaw()
}

func TestNvtxNestedPushPopIsOneTrace(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.name(samples.NvtxResourceDomain, 1, "TensorRT-LLM")
	h.name(samples.NvtxResourceOSThread, 7, "executor")
	h.ev(7, samples.NvtxKindRangePush, 1, 0, "executor_loop", 0)
	h.ev(7, samples.NvtxKindRangePush, 1, 0, "_forward_step", 1)
	h.ev(7, samples.NvtxKindMark, 1, 0, "batch_ready", 2)
	h.ev(7, samples.NvtxKindRangePop, 1, 0, "", 5)
	h.ev(7, samples.NvtxKindRangePop, 1, 0, "", 9)
	h.flush()

	require.Len(t, h.spans, 2)
	root, child := h.span("executor_loop"), h.span("_forward_step")
	assert.True(t, root.ParentSpanID().IsEmpty())
	assert.Equal(t, root.TraceID(), child.TraceID())
	assert.Equal(t, root.SpanID(), child.ParentSpanID())
	assert.Equal(t, int64(9*time.Millisecond), int64(root.EndTimestamp()-root.StartTimestamp()))
	assert.Equal(t, int64(4*time.Millisecond), int64(child.EndTimestamp()-child.StartTimestamp()))
	assert.Equal(t, "TensorRT-LLM", attr(child, "nvtx.domain"))
	assert.Equal(t, "executor", attr(child, "thread.name"))
	assert.Equal(t, int64(7), attr(child, "thread.id"))
	assert.Nil(t, attr(child, "cuda.device_id"), "unknown device is omitted")
	assert.Equal(t, "trtllm", h.res[0].AsRaw()["service.name"])

	require.Equal(t, 1, child.Events().Len(), "mark lands on the innermost open range")
	assert.Equal(t, "batch_ready", child.Events().At(0).Name())
	assert.Equal(t, 0, root.Events().Len())
	assert.Empty(t, h.marks)
}

func TestNvtxSeparateTopLevelRangesAreSeparateTraces(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	for i := range 2 {
		h.ev(7, samples.NvtxKindRangePush, 0, 0, "step", int64(i*10))
		h.ev(7, samples.NvtxKindRangePop, 0, 0, "", int64(i*10+5))
	}
	h.flush()
	require.Len(t, h.spans, 2)
	assert.NotEqual(t, h.spans[0].TraceID(), h.spans[1].TraceID())
}

func TestNvtxThreadsAndDomainsHaveTheirOwnStacks(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.ev(7, samples.NvtxKindRangePush, 0, 0, "outer", 0)
	h.ev(8, samples.NvtxKindRangePush, 0, 0, "other_thread", 1)
	h.ev(7, samples.NvtxKindRangePush, 2, 0, "inner_domain2", 2)
	// Pops for domain 0 on thread 7 close "outer", not the domain-2 range
	// opened after it.
	h.ev(7, samples.NvtxKindRangePop, 0, 0, "", 3)
	h.ev(7, samples.NvtxKindRangePop, 2, 0, "", 4)
	h.ev(8, samples.NvtxKindRangePop, 0, 0, "", 5)
	h.flush()

	require.Len(t, h.spans, 3)
	outer, inner, other := h.span("outer"), h.span("inner_domain2"), h.span("other_thread")
	assert.Equal(t, outer.SpanID(), inner.ParentSpanID())
	assert.Equal(t, int64(3*time.Millisecond), int64(outer.EndTimestamp()-outer.StartTimestamp()))
	assert.True(t, other.ParentSpanID().IsEmpty())
	assert.NotEqual(t, outer.TraceID(), other.TraceID())
	assert.Equal(t, int64(2), attr(inner, "nvtx.domain_id"), "unnamed domain falls back to its id")
}

func TestNvtxStartEndAcrossThreads(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.ev(7, samples.NvtxKindRangePush, 0, 0, "request", 0)
	h.ev(7, samples.NvtxKindRangeStart, 0, 42, "async_copy", 1)
	h.ev(7, samples.NvtxKindRangePop, 0, 0, "", 2)
	h.ev(9, samples.NvtxKindRangeEnd, 0, 42, "", 8)
	h.flush()

	require.Len(t, h.spans, 2)
	req, cp := h.span("request"), h.span("async_copy")
	assert.Equal(t, req.SpanID(), cp.ParentSpanID())
	assert.Equal(t, int64(7*time.Millisecond), int64(cp.EndTimestamp()-cp.StartTimestamp()))
	assert.Equal(t, int64(42), attr(cp, "nvtx.range_id"))
}

func TestNvtxEndBeforeStartIsHeld(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	// The ending thread's batch was flushed before the starting thread's.
	h.ev(9, samples.NvtxKindRangeEnd, 0, 42, "", 8)
	h.flush()
	assert.Empty(t, h.spans)
	h.ev(7, samples.NvtxKindRangeStart, 0, 42, "late_start", 1)
	h.flush()
	require.Len(t, h.spans, 1)
	assert.Equal(t, int64(7*time.Millisecond), int64(h.spans[0].EndTimestamp()-h.spans[0].StartTimestamp()))

	// An end whose start never shows up is eventually forgotten.
	h.ev(9, samples.NvtxKindRangeEnd, 0, 43, "", 0)
	h.now = h.now.Add(nvtxPendingEndTTL + time.Second)
	h.flush()
	assert.Empty(t, h.tr.procs[testPID].pendingEnds)
	assert.Equal(t, uint64(1), h.tr.stats.unmatched.Load())
}

func TestNvtxUnmatchedPopIsIgnored(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.ev(7, samples.NvtxKindRangePop, 0, 0, "", 0)
	h.flush()
	assert.Empty(t, h.spans)
	assert.Equal(t, uint64(1), h.tr.stats.unmatched.Load())
}

func TestNvtxMarkOutsideRangeIsLogged(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.name(samples.NvtxResourceDomain, 1, "TensorRT-LLM")
	h.ev(7, samples.NvtxKindMark, 1, 0, "loaded", 3)
	h.flush()
	assert.Empty(t, h.spans)
	require.Len(t, h.marks, 1)
	rec := h.marks[0]
	assert.Equal(t, "nvtx.mark", rec.EventName())
	assert.Equal(t, h.now.Add(3*time.Millisecond).UnixNano(), int64(rec.Timestamp()))
	got := rec.Attributes().AsRaw()
	assert.Equal(t, "loaded", got["nvtx.message"])
	assert.Equal(t, "TensorRT-LLM", got["nvtx.domain"])
	assert.Equal(t, "trtllm", h.mres[0].AsRaw()["service.name"],
		"marks carry the process's resource, not the agent's")
}

func TestNvtxMarksPerFlushAreCapped(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	for i := range nvtxMaxMarksPerFlush + 5 {
		h.ev(7, samples.NvtxKindMark, 0, 0, "m", int64(i))
	}
	h.flush()
	assert.Len(t, h.marks, nvtxMaxMarksPerFlush)
	assert.Equal(t, uint64(5), h.tr.stats.markDrops.Load())

	h.ev(7, samples.NvtxKindMark, 0, 0, "after", 0)
	h.flush()
	assert.Len(t, h.marks, nvtxMaxMarksPerFlush+1, "the cap is per flush")
}

func TestNvtxProcessExitClosesOpenRanges(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.ev(7, samples.NvtxKindRangePush, 0, 0, "train", 0)
	h.ev(7, samples.NvtxKindRangePush, 0, 0, "epoch", 1)
	h.ev(7, samples.NvtxKindMark, 0, 0, "checkpoint", 4)
	h.flush()
	assert.Empty(t, h.spans, "ranges stay open while the process lives")

	h.alive[testPID] = false
	h.flush()
	require.Len(t, h.spans, 2)
	for _, s := range h.spans {
		assert.Equal(t, true, attr(s, "nvtx.unclosed"), s.Name())
		assert.Equal(t, h.now.Add(4*time.Millisecond).UnixNano(), int64(s.EndTimestamp()),
			"ended at the process's last event")
	}
	assert.Empty(t, h.tr.procs)
}

type lifetimeMetadata map[string]string

func (m lifetimeMetadata) AddMetadata(_ context.Context, _ libpf.PID, lb *labels.Builder) bool {
	for k, v := range m {
		lb.Set(k, v)
	}
	// Bypass resolver caching to exercise loss of metadata independently of
	// the label TTL, and to detect accidental PID-based snapshot reuse.
	return false
}

func TestGPUAndNvtxResourcesSurviveProcessExit(t *testing.T) {
	for _, exit := range []bool{false, true} {
		t.Run(fmt.Sprintf("exit=%t", exit), func(t *testing.T) {
			meta := lifetimeMetadata{}
			resolver, err := processlabels.New(processlabels.Config{
				CacheSize: 16,
				Providers: []metadata.MetadataProvider{meta},
			})
			require.NoError(t, err)
			h := newHarness(t, NvtxTracerConfig{})
			h.tr.resourcer = gpumetrics.NewProcessResourcer(t.Context(), resolver, nil, "gpu-node", true)
			metricResolver, err := resolver.Fork()
			require.NoError(t, err)
			producer := gpumetrics.NewProducer(nil)
			producer.SetProcessResourcer(gpumetrics.NewProcessResourcer(t.Context(), metricResolver, nil, "gpu-node", true))

			// A second batch with the same PID must capture fresh metadata,
			// both for a live process and after reaping an exited process.
			for _, uid := range []string{"4b375b5e-1093-4a8f-846d-0c1ef8b6a5d2", "d496ac67-0f8c-4616-9950-a411a0ef122e"} {
				meta["k8s.pod.uid"] = uid
				meta["container.id"] = "container-" + uid
				h.alive[testPID] = true
				h.ev(7, samples.NvtxKindRangePush, 0, 0, "step", 0)
				h.ev(7, samples.NvtxKindMark, 0, 0, "inside", 1)
				producer.RecordProcess(testPID, func(b *gpumetrics.MetricBuffer) {
					b.Points(gpumetrics.MetricProcessUtilization).AppendEmpty().SetDoubleValue(0.3)
				})
				h.flush() // An open range must retain identity across empty flushes.
				if exit {
					clear(meta)
					h.alive[testPID] = false
				} else {
					h.ev(7, samples.NvtxKindRangePop, 0, 0, "", 3)
				}
				// Queued events can be handled after the process has exited.
				h.ev(8, samples.NvtxKindMark, 0, 0, "outside", 4)
				h.flush()
				resources := pmetric.NewResourceMetricsSlice()
				require.NoError(t, producer.Produce(pmetric.NewMetricSlice(), resources))
				require.Equal(t, 1, resources.Len())
				require.NotEmpty(t, h.spans)
				require.NotEmpty(t, h.marks)
				for _, attrs := range []pcommon.Map{h.res[len(h.res)-1], h.mres[len(h.mres)-1], resources.At(0).Resource().Attributes()} {
					assert.Equal(t, uid, attrs.AsRaw()["k8s.pod.uid"])
					assert.Equal(t, "container-"+uid, attrs.AsRaw()["container.id"])
				}
			}
		})
	}
}

func TestNvtxBudgetKeepsOrDropsWholeTraces(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{MaxSpansPerSec: 3})
	// Each trace is a root with two children: 3 spans.
	trace := func(at int64) {
		h.ev(7, samples.NvtxKindRangePush, 0, 0, "root", at)
		h.ev(7, samples.NvtxKindRangePush, 0, 0, "child", at+1)
		h.ev(7, samples.NvtxKindRangePop, 0, 0, "", at+2)
		h.ev(7, samples.NvtxKindRangePush, 0, 0, "child", at+3)
		h.ev(7, samples.NvtxKindRangePop, 0, 0, "", at+4)
		h.ev(7, samples.NvtxKindRangePop, 0, 0, "", at+5)
	}
	trace(0)
	trace(10) // budget spent: dropped whole
	h.flush()
	require.Len(t, h.spans, 3)
	for _, s := range h.spans {
		assert.Equal(t, h.spans[0].TraceID(), s.TraceID())
	}
	assert.Equal(t, uint64(3), h.tr.stats.sampledOut.Load())

	h.now = h.now.Add(time.Second) // refilled
	trace(0)
	h.flush()
	assert.Len(t, h.spans, 6)
}

func TestNvtxStackDepthIsBounded(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	for i := range nvtxMaxDepth + 1 {
		h.ev(7, samples.NvtxKindRangePush, 0, 0, "deep", int64(i))
	}
	h.flush()
	require.Len(t, h.spans, 1, "the oldest range is closed to make room")
	assert.Equal(t, true, attr(h.spans[0], "nvtx.unclosed"))
	assert.Len(t, h.tr.procs[testPID].threads[7], nvtxMaxDepth)
}

func TestNvtxRelabelDropsProcess(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	h.tr.resourcer = fakeResourcer{drop: map[uint32]bool{testPID: true}}
	h.ev(7, samples.NvtxKindRangePush, 0, 0, "step", 0)
	h.ev(7, samples.NvtxKindRangePop, 0, 0, "", 1)
	h.flush()
	assert.Empty(t, h.spans)
}

func TestNvtxReportCopiesStrings(t *testing.T) {
	h := newHarness(t, NvtxTracerConfig{})
	buf := []byte("forward_step")
	msg := unsafe.String(&buf[0], len(buf)) // aliases buf, like pfunsafe.ToString
	require.NoError(t, h.tr.ReportNvtxEvent(&samples.NvtxEvent{
		PID: testPID, TID: 7, Kind: samples.NvtxKindRangePush, Message: msg,
	}))
	copy(buf, "XXXXXXXXXXXX") // the ringbuf reuses its buffer
	in := <-h.tr.in
	assert.Equal(t, "forward_step", in.ev.Message)
}
