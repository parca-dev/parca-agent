//go:build linux

package probes

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/parca-dev/parca-agent/reporter"
)

// spanName is the OTel span name emitted for every paired-scope event.
// Stable string so dashboards can filter on it.
const spanName = "node.callback_scope"

// tracerScope is the instrumentation-scope name on the OTel Tracer we obtain
// from the reporter. Using a probe-specific scope lets consumers slice
// probe spans vs other spans by the scope name.
const tracerScope = "parca-agent.probes"

// StartConfig is the small bag of parameters Service.Start needs in addition
// to the YAML probe-config path.
type StartConfig struct {
	ConfigPath string // path to probe-config YAML; required
}

// Service owns the BPF programs, the attach worker, and the ringbuf drain
// loop. Drained events are emitted as OTel spans via the Tracer handed out
// by reporter.ParcaReporter; the reporter owns the underlying OTLP pipeline
// (queue, batch, retry, transport). Construct with Start, tear down with
// Close.
type Service struct {
	cfg      StartConfig
	specs    []ProbeSpec
	specByID map[uint32]ProbeSpec

	bpf      *loadedBPF
	attacher *attacher

	tracer oteltrace.Tracer

	rootCancel context.CancelFunc
	wg         sync.WaitGroup
}

// Start parses the YAML, loads the BPF programs, and spawns the drain and
// attach goroutines. It does NOT attach any uprobes yet -- those happen as
// OnExecutable is invoked by the profiler for each newly-observed binary.
func Start(ctx context.Context, cfg StartConfig, rep reporter.ParcaReporter) (*Service, error) {
	if cfg.ConfigPath == "" {
		return nil, errors.New("probes: ConfigPath is required")
	}
	if rep == nil {
		return nil, errors.New("probes: reporter is required")
	}

	specs, err := LoadConfig(cfg.ConfigPath)
	if err != nil {
		return nil, err
	}
	specByID := make(map[uint32]ProbeSpec, len(specs))
	for _, s := range specs {
		specByID[s.SpecID] = s
	}
	log.Infof("probes: loaded %d probe specs from %s", len(specs), cfg.ConfigPath)

	bpf, err := loadBPF()
	if err != nil {
		return nil, fmt.Errorf("probes: %w", err)
	}

	att := newAttacher(bpf.objs.ProbeEntry, bpf.objs.ProbeExit, specs, 256)

	rootCtx, cancel := context.WithCancel(ctx)

	s := &Service{
		cfg:        cfg,
		specs:      specs,
		specByID:   specByID,
		bpf:        bpf,
		attacher:   att,
		tracer:     rep.Tracer(tracerScope),
		rootCancel: cancel,
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.drainLoop(rootCtx)
	}()
	go func() {
		defer s.wg.Done()
		att.run(rootCtx)
	}()

	return s, nil
}

// OnExecutable forwards a newly-observed binary to the attach worker. Safe
// to call from any goroutine; cheap on the hot path.
func (s *Service) OnExecutable(filePath string, fileID libpf.FileID) {
	if s == nil {
		return
	}
	s.attacher.OnExecutable(filePath, fileID)
}

// Close cancels the service's root context, waits for goroutines to drain,
// closes attached uprobe links, and releases BPF resources.
//
// Closing the ringbuf reader is required BEFORE waiting on the WaitGroup:
// the drain goroutine is parked inside reader.Read(), which only returns
// when an event arrives or the reader is closed. The drain loop's ctx.Done
// check at the top of each iteration never gets revisited while Read is
// blocked, so cancelling the context alone is not enough to unblock it.
// Closing the reader makes Read return; the drain loop then sees the
// already-cancelled context and exits.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.rootCancel()
	if s.bpf != nil && s.bpf.reader != nil {
		_ = s.bpf.reader.Close()
	}
	s.wg.Wait()
	s.attacher.closeAllLinks()
	return s.bpf.Close()
}

// drainLoop reads from the BPF ringbuf, decodes events, looks up spec_id, and
// emits an OTel log record per (ctor, dtor) pair. Each record represents one
// completed outer JS callback whose duration was measured in-kernel and is
// carried as the `duration_ns` attribute.
func (s *Service) drainLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := s.bpf.reader.Read()
		if err != nil {
			if errors.Is(err, syscall.EBADF) || ctx.Err() != nil {
				return
			}
			log.Warnf("probes: ringbuf read: %v", err)
			return
		}
		if len(rec.RawSample) < int(unsafe.Sizeof(probeProbeEvent{})) {
			log.Warnf("probes: ringbuf record too short: %d bytes", len(rec.RawSample))
			continue
		}
		raw := *(*probeProbeEvent)(unsafe.Pointer(&rec.RawSample[0]))
		spec, ok := s.specByID[raw.SpecId]
		if !ok {
			log.Warnf("probes: unknown spec_id=%d in event", raw.SpecId)
			continue
		}

		// The BPF program emits the EXIT ktime (CLOCK_MONOTONIC ns). We
		// convert it via the upstream times package, which uses the same
		// atomic ktime->unix offset (refreshed by StartRealtimeSync) that
		// the ebpf-profiler applies to its CPU sample timestamps. That
		// guarantees probe spans and profile samples share identical
		// wall-clock conversion, so range queries like "samples within
		// the span's [start, end]" never drift across the two pipelines.
		endNs := times.KTime(raw.KtimeNs).UnixNano()
		startNs := endNs - int64(raw.DurationNs)

		// Backdate the span's start and end to the kernel timestamps. The
		// SDK would otherwise stamp Start()/End() with time.Now(), which is
		// strictly later than when the callback actually ran. Spans have no
		// parent context -- each probe fire is a root span.
		_, span := s.tracer.Start(ctx, spanName,
			oteltrace.WithSpanKind(oteltrace.SpanKindInternal),
			oteltrace.WithTimestamp(time.Unix(0, startNs)),
			oteltrace.WithAttributes(
				attribute.Int64("duration_ns", int64(raw.DurationNs)),
				attribute.Int64("pid", int64(raw.Pid)),
				attribute.Int64("tid", int64(raw.Tid)),
				attribute.String("comm", trimComm(&raw.Comm)),
				attribute.Int64("spec_id", int64(raw.SpecId)),
				attribute.String("probe_id", spec.ID),
			),
		)
		span.End(oteltrace.WithTimestamp(time.Unix(0, endNs)))

		// Per-fire debug. Level-guarded so we don't allocate the WithFields
		// map on the hot path when debug is off. Tagged otlp_skip so the
		// debug record itself doesn't get re-shipped via --otlp-logging.
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				reporter.OTLPSkipField: true,
				"probe_id":             spec.ID,
				"pid":                  raw.Pid,
				"tid":                  raw.Tid,
				"comm":                 trimComm(&raw.Comm),
				"duration_ms":          raw.DurationNs / 1_000_000,
			}).Debug("probe fire")
		}
	}
}

// trimComm renders the kernel's null-padded comm bytes as a Go string.
// bpf2go emits the C `char[16]` field as `[16]int8`; we reinterpret it
// as a byte slice via unsafe.Slice (identical memory layout) and trim at
// the first NUL.
func trimComm(b *[16]int8) string {
	bs := unsafe.Slice((*byte)(unsafe.Pointer(b)), len(b))
	for i, c := range bs {
		if c == 0 {
			return string(bs[:i])
		}
	}
	return string(bs)
}
