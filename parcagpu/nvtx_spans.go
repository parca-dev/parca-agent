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
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/internal/log"

	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// NvtxScope is the instrumentation scope of NVTX spans, and of the log
// records for marks made outside any range.
const NvtxScope = "parca-agent.nvtx"

const (
	nvtxQueueSize = 16384
	// An end can arrive before its start when the two were on different
	// threads: each thread's events are batched and flushed independently
	// (parcagpu flushes a batch at the latest 100ms after its first event).
	nvtxPendingEndTTL = 2 * time.Second
	// Bounds a thread's open-range stack when an app pushes without popping.
	// The oldest range is closed as unclosed to make room.
	nvtxMaxDepth      = 256
	nvtxFlushInterval = time.Second
	nvtxExportTimeout = 10 * time.Second
)

// ProcessResourcer renders a process's OTLP resource attributes; see
// gpumetrics.ProcessResourcer, which this matches so NVTX spans carry the same
// resource as the process's profiles.
type ProcessResourcer interface {
	PutResource(pid uint32, attrs pcommon.Map) bool
}

// TraceExportFunc sends one batch of spans.
type TraceExportFunc func(context.Context, ptrace.Traces) error

// NewOTLPTraceExport returns a TraceExportFunc that sends over conn.
func NewOTLPTraceExport(conn *grpc.ClientConn) TraceExportFunc {
	client := ptraceotlp.NewGRPCClient(conn)
	return func(ctx context.Context, td ptrace.Traces) error {
		resp, err := client.Export(ctx, ptraceotlp.NewExportRequestFromTraces(td))
		if err != nil {
			return err
		}
		if ps := resp.PartialSuccess(); ps.RejectedSpans() > 0 {
			return fmt.Errorf("%d spans rejected: %s", ps.RejectedSpans(), ps.ErrorMessage())
		}
		return nil
	}
}

// NvtxTracerConfig configures an NvtxTracer.
type NvtxTracerConfig struct {
	// MaxSpansPerSec is each process's span budget. Whole traces are kept or
	// dropped when their top-level range opens; 0 means unlimited.
	MaxSpansPerSec float64
}

// NvtxTracer turns NVTX events into OTLP spans. Each top-level range on a
// thread starts a trace; ranges opened inside it are its descendants. Push/pop
// ranges nest per thread; start/end ranges pair by range id and may end on
// another thread. A mark becomes an event on the innermost open range of its
// thread, or a log record if no range is open.
//
// It implements reporter.NvtxReporter. Events are queued and processed in
// order by Run, so ReportNvtxEvent never blocks the ringbuf reader.
type NvtxTracer struct {
	cfg       NvtxTracerConfig
	resourcer ProcessResourcer
	export    TraceExportFunc
	marks     otellog.Logger // nil: marks outside ranges are dropped

	in    chan nvtxInput
	procs map[uint32]*nvtxProc

	// Overridable in tests.
	now       func() time.Time
	procAlive func(pid uint32) bool

	stats nvtxStats
}

var _ reporter.NvtxReporter = (*NvtxTracer)(nil)

type nvtxStats struct {
	queueDrops, spans, sampledOut, unmatched, exportErrors atomic.Uint64
}

type nvtxInput struct {
	ev   samples.NvtxEvent
	name *samples.NvtxResourceNameEvent
}

type nvtxProc struct {
	threads     map[uint32][]*nvtxSpan // open push/pop and start/end ranges, by thread
	ranges      map[uint64]*nvtxSpan   // open start/end ranges, by range id
	pendingEnds map[uint64]nvtxPendingEnd
	threadNames map[uint32]string
	domainNames map[uint32]string
	tokens      float64
	refilled    time.Time
	lastEventNs int64
	out         ptrace.SpanSlice // finished spans awaiting export
}

type nvtxPendingEnd struct {
	ns      int64
	arrived time.Time
}

type nvtxSpan struct {
	traceID  pcommon.TraceID
	spanID   pcommon.SpanID
	parentID pcommon.SpanID
	kept     bool
	pushPop  bool
	rangeID  uint64
	domain   uint32
	tid      uint32
	name     string
	startNs  int64
	color    uint32
	payload  uint64
	deviceID uint32
	marks    []samples.NvtxEvent
}

// NewNvtxTracer returns a tracer exporting through export. marks receives
// marks made outside any range; it may be nil.
func NewNvtxTracer(cfg NvtxTracerConfig, resourcer ProcessResourcer, export TraceExportFunc,
	marks otellog.Logger,
) *NvtxTracer {
	return &NvtxTracer{
		cfg:       cfg,
		resourcer: resourcer,
		export:    export,
		marks:     marks,
		in:        make(chan nvtxInput, nvtxQueueSize),
		procs:     make(map[uint32]*nvtxProc),
		now:       time.Now,
		procAlive: func(pid uint32) bool {
			_, err := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10))
			return err == nil
		},
	}
}

var errNvtxQueueFull = errors.New("nvtx queue full")

// ReportNvtxEvent implements reporter.NvtxReporter.
func (t *NvtxTracer) ReportNvtxEvent(ev *samples.NvtxEvent) error {
	in := nvtxInput{ev: *ev}
	in.ev.Message = strings.Clone(ev.Message)
	return t.enqueue(in)
}

// ReportNvtxResourceName implements reporter.NvtxReporter.
func (t *NvtxTracer) ReportNvtxResourceName(ev *samples.NvtxResourceNameEvent) error {
	name := *ev
	name.Name = strings.Clone(ev.Name)
	return t.enqueue(nvtxInput{name: &name})
}

func (t *NvtxTracer) enqueue(in nvtxInput) error {
	select {
	case t.in <- in:
		return nil
	default:
		t.stats.queueDrops.Add(1)
		return errNvtxQueueFull
	}
}

// Run processes events until ctx is done, then closes every open range and
// exports what is left.
func (t *NvtxTracer) Run(ctx context.Context) {
	ticker := time.NewTicker(nvtxFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case in := <-t.in:
			t.handle(in)
		case <-ticker.C:
			t.flush(ctx, false)
		case <-ctx.Done():
			// The parent context is done; give the last export its own.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), nvtxExportTimeout)
			t.flush(shutdownCtx, true)
			cancel()
			return
		}
	}
}

func (t *NvtxTracer) handle(in nvtxInput) {
	if in.name != nil {
		p := t.proc(in.name.PID)
		switch in.name.Kind {
		case samples.NvtxResourceOSThread:
			p.threadNames[uint32(in.name.ID)] = in.name.Name
		case samples.NvtxResourceDomain:
			p.domainNames[uint32(in.name.ID)] = in.name.Name
		}
		return
	}

	ev := &in.ev
	p := t.proc(ev.PID)
	p.lastEventNs = max(p.lastEventNs, ev.TimeUnixNano)
	switch ev.Kind {
	case samples.NvtxKindRangePush:
		t.open(p, ev, true)
	case samples.NvtxKindRangePop:
		stack := p.threads[ev.TID]
		for i := len(stack) - 1; i >= 0; i-- {
			if s := stack[i]; s.pushPop && s.domain == ev.DomainID {
				p.threads[ev.TID] = append(stack[:i], stack[i+1:]...)
				t.finish(p, s, ev.TimeUnixNano, false)
				return
			}
		}
		// Typically the agent attached while the range was open.
		t.stats.unmatched.Add(1)
	case samples.NvtxKindRangeStart:
		s := t.open(p, ev, false)
		p.ranges[ev.RangeID] = s
		if end, ok := p.pendingEnds[ev.RangeID]; ok {
			delete(p.pendingEnds, ev.RangeID)
			t.end(p, s, end.ns)
		}
	case samples.NvtxKindRangeEnd:
		if s, ok := p.ranges[ev.RangeID]; ok {
			t.end(p, s, ev.TimeUnixNano)
			return
		}
		p.pendingEnds[ev.RangeID] = nvtxPendingEnd{ns: ev.TimeUnixNano, arrived: t.now()}
	case samples.NvtxKindMark:
		if stack := p.threads[ev.TID]; len(stack) > 0 {
			if s := stack[len(stack)-1]; s.kept {
				s.marks = append(s.marks, *ev)
			}
			return
		}
		t.logMark(ev)
	}
}

func (t *NvtxTracer) proc(pid uint32) *nvtxProc {
	p := t.procs[pid]
	if p == nil {
		p = &nvtxProc{
			threads:     make(map[uint32][]*nvtxSpan),
			ranges:      make(map[uint64]*nvtxSpan),
			pendingEnds: make(map[uint64]nvtxPendingEnd),
			threadNames: make(map[uint32]string),
			domainNames: make(map[uint32]string),
			tokens:      t.cfg.MaxSpansPerSec,
			refilled:    t.now(),
			out:         ptrace.NewSpanSlice(),
		}
		t.procs[pid] = p
	}
	return p
}

// open starts a span for a push or start event, as a child of the innermost
// open range on the event's thread or else as the root of a new trace.
func (t *NvtxTracer) open(p *nvtxProc, ev *samples.NvtxEvent, pushPop bool) *nvtxSpan {
	s := &nvtxSpan{
		spanID:   newSpanID(),
		pushPop:  pushPop,
		rangeID:  ev.RangeID,
		domain:   ev.DomainID,
		tid:      ev.TID,
		name:     ev.Message,
		startNs:  ev.TimeUnixNano,
		color:    ev.Color,
		payload:  ev.Payload,
		deviceID: ev.DeviceID,
	}
	stack := p.threads[ev.TID]
	if len(stack) > 0 {
		parent := stack[len(stack)-1]
		s.traceID, s.parentID, s.kept = parent.traceID, parent.spanID, parent.kept
	} else {
		s.traceID = newTraceID()
		s.kept = t.admitTrace(p)
	}
	if s.kept {
		// Descendants of an admitted trace are always kept, so a trace is
		// never split; they still draw on the budget, which can go into debt
		// and delays admitting the next trace.
		p.tokens--
	}
	if len(stack) >= nvtxMaxDepth {
		t.close(p, stack[0], ev.TimeUnixNano)
		stack = stack[1:]
	}
	p.threads[ev.TID] = append(stack, s)
	return s
}

func (t *NvtxTracer) admitTrace(p *nvtxProc) bool {
	if t.cfg.MaxSpansPerSec <= 0 {
		return true
	}
	now := t.now()
	p.tokens = min(p.tokens+now.Sub(p.refilled).Seconds()*t.cfg.MaxSpansPerSec, t.cfg.MaxSpansPerSec)
	p.refilled = now
	return p.tokens >= 1
}

// end finishes a start/end range and takes it off its thread's stack.
func (t *NvtxTracer) end(p *nvtxProc, s *nvtxSpan, ns int64) {
	delete(p.ranges, s.rangeID)
	t.unstack(p, s)
	t.finish(p, s, ns, false)
}

// close finishes s as unclosed, e.g. when its process exited or its thread's
// stack overflowed.
func (t *NvtxTracer) close(p *nvtxProc, s *nvtxSpan, ns int64) {
	if !s.pushPop {
		delete(p.ranges, s.rangeID)
	}
	t.finish(p, s, ns, true)
}

func (t *NvtxTracer) unstack(p *nvtxProc, s *nvtxSpan) {
	stack := p.threads[s.tid]
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == s {
			p.threads[s.tid] = append(stack[:i], stack[i+1:]...)
			return
		}
	}
}

func (t *NvtxTracer) finish(p *nvtxProc, s *nvtxSpan, endNs int64, unclosed bool) {
	if !s.kept {
		t.stats.sampledOut.Add(1)
		return
	}
	t.stats.spans.Add(1)
	span := p.out.AppendEmpty()
	span.SetTraceID(s.traceID)
	span.SetSpanID(s.spanID)
	span.SetParentSpanID(s.parentID)
	span.SetKind(ptrace.SpanKindInternal)
	name := s.name
	if name == "" {
		name = "nvtx.range"
	}
	span.SetName(name)
	span.SetStartTimestamp(pcommon.Timestamp(s.startNs))
	span.SetEndTimestamp(pcommon.Timestamp(max(endNs, s.startNs)))

	attrs := span.Attributes()
	attrs.PutInt("thread.id", int64(s.tid))
	if name := p.threadNames[s.tid]; name != "" {
		attrs.PutStr("thread.name", name)
	}
	putDomain(attrs, p, s.domain)
	putColorPayload(attrs, s.color, s.payload)
	if s.deviceID != math.MaxUint32 {
		attrs.PutInt("cuda.device_id", int64(s.deviceID))
	}
	if !s.pushPop {
		attrs.PutInt("nvtx.range_id", int64(s.rangeID))
	}
	if unclosed {
		attrs.PutBool("nvtx.unclosed", true)
	}

	for i := range s.marks {
		m := &s.marks[i]
		e := span.Events().AppendEmpty()
		e.SetName(m.Message)
		if m.Message == "" {
			e.SetName("nvtx.mark")
		}
		e.SetTimestamp(pcommon.Timestamp(m.TimeUnixNano))
		if m.DomainID != s.domain {
			putDomain(e.Attributes(), p, m.DomainID)
		}
		putColorPayload(e.Attributes(), m.Color, m.Payload)
	}
}

func putDomain(attrs pcommon.Map, p *nvtxProc, domain uint32) {
	if domain == 0 {
		return
	}
	if name := p.domainNames[domain]; name != "" {
		attrs.PutStr("nvtx.domain", name)
	} else {
		// Named on a later re-announce; parcagpu repeats it every 30s.
		attrs.PutInt("nvtx.domain_id", int64(domain))
	}
}

func putColorPayload(attrs pcommon.Map, color uint32, payload uint64) {
	if color != 0 {
		attrs.PutStr("nvtx.color", "0x"+strconv.FormatUint(uint64(color), 16))
	}
	if payload != 0 {
		attrs.PutInt("nvtx.payload", int64(payload))
	}
}

// flush expires stale state, closes the ranges of exited processes (or of
// every process when final) and exports finished spans.
func (t *NvtxTracer) flush(ctx context.Context, final bool) {
	now := t.now()
	td := ptrace.NewTraces()
	for pid, p := range t.procs {
		for id, end := range p.pendingEnds {
			if now.Sub(end.arrived) > nvtxPendingEndTTL {
				delete(p.pendingEnds, id)
				t.stats.unmatched.Add(1)
			}
		}
		exited := final || !t.procAlive(pid)
		if exited {
			for _, stack := range p.threads {
				for _, s := range stack {
					t.close(p, s, p.lastEventNs)
				}
			}
			delete(t.procs, pid)
		}
		if p.out.Len() == 0 {
			continue
		}
		rs := ptrace.NewResourceSpans()
		if !t.resourcer.PutResource(pid, rs.Resource().Attributes()) {
			// A relabel rule dropped the process.
			p.out = ptrace.NewSpanSlice()
			continue
		}
		rs.SetSchemaUrl(processlabels.SchemaURL)
		ss := rs.ScopeSpans().AppendEmpty()
		ss.Scope().SetName(NvtxScope)
		p.out.MoveAndAppendTo(ss.Spans())
		rs.MoveTo(td.ResourceSpans().AppendEmpty())
	}

	if td.SpanCount() > 0 {
		exportCtx, cancel := context.WithTimeout(ctx, nvtxExportTimeout)
		err := t.export(exportCtx, td)
		cancel()
		if err != nil {
			t.stats.exportErrors.Add(1)
			log.Warnf("[cuda] nvtx span export failed (%d spans dropped): %v", td.SpanCount(), err)
		}
	}
	if final {
		log.Debugf("[cuda] nvtx: spans=%d sampled_out=%d unmatched=%d queue_drops=%d export_errors=%d",
			t.stats.spans.Load(), t.stats.sampledOut.Load(), t.stats.unmatched.Load(),
			t.stats.queueDrops.Load(), t.stats.exportErrors.Load())
	}
}

// logMark emits a mark made outside any range as a log record.
func (t *NvtxTracer) logMark(ev *samples.NvtxEvent) {
	if t.marks == nil {
		return
	}
	var rec otellog.Record
	rec.SetTimestamp(time.Unix(0, ev.TimeUnixNano))
	rec.SetObservedTimestamp(t.now())
	rec.SetEventName("nvtx.mark")
	rec.SetBody(attribute.StringValue("nvtx.mark"))
	rec.AddAttributes(
		attribute.Int64("process.pid", int64(ev.PID)),
		attribute.Int64("thread.id", int64(ev.TID)),
	)
	if ev.Message != "" {
		rec.AddAttributes(attribute.String("nvtx.message", ev.Message))
	}
	if p := t.procs[ev.PID]; p != nil && ev.DomainID != 0 {
		if name := p.domainNames[ev.DomainID]; name != "" {
			rec.AddAttributes(attribute.String("nvtx.domain", name))
		} else {
			rec.AddAttributes(attribute.Int64("nvtx.domain_id", int64(ev.DomainID)))
		}
	}
	if ev.Color != 0 {
		rec.AddAttributes(attribute.String("nvtx.color", "0x"+strconv.FormatUint(uint64(ev.Color), 16)))
	}
	if ev.Payload != 0 {
		rec.AddAttributes(attribute.Int64("nvtx.payload", int64(ev.Payload)))
	}
	t.marks.Emit(context.Background(), rec)
}

func newTraceID() pcommon.TraceID {
	var id pcommon.TraceID
	putUint64(id[:8], rand.Uint64())
	putUint64(id[8:], rand.Uint64())
	return id
}

func newSpanID() pcommon.SpanID {
	var id pcommon.SpanID
	for id.IsEmpty() {
		putUint64(id[:], rand.Uint64())
	}
	return id
}

func putUint64(b []byte, v uint64) {
	for i := range 8 {
		b[i] = byte(v >> (8 * i))
	}
}
