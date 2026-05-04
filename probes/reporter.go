//go:build linux

package probes

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	arrowv1 "github.com/open-telemetry/otel-arrow/go/api/experimental/arrow/v1"
	"github.com/open-telemetry/otel-arrow/go/pkg/otel/arrow_record"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"google.golang.org/grpc"
)

// LogEvent is the userspace representation of one probe firing, after the
// drain loop has resolved spec_id back to the probe's symbol name.
type LogEvent struct {
	TimestampNs         int64 // ktime_ns + wallOffset, ns since unix epoch
	ObservedTimestampNs int64 // wall-clock now() at dequeue
	PID                 uint32
	TID                 uint32
	Comm                string
	SpecID              uint32
	ProbeName           string
}

const (
	defaultBatchSize  = 512
	defaultBatchAge   = 250 * time.Millisecond
	defaultEventQueue = 4096
	streamRedialDelay = 5 * time.Second
)

// streamerOptions is the resource-attribute payload attached to every batch.
type streamerOptions struct {
	ServiceName    string // service.name = "parca-agent"
	ServiceVersion string // service.version = build VCS revision
	HostName       string // host.name = agent --node
}

type streamer struct {
	conn *grpc.ClientConn
	opts streamerOptions

	in <-chan LogEvent

	// counters
	batchesSent atomic.Uint64
	eventsSent  atomic.Uint64
	streamErrs  atomic.Uint64
}

func newStreamer(conn *grpc.ClientConn, opts streamerOptions, in <-chan LogEvent) *streamer {
	return &streamer{conn: conn, opts: opts, in: in}
}

// run batches LogEvents and pushes them as BatchArrowRecords on the
// ArrowLogsService bidi stream. Reconnects on stream error.
func (s *streamer) run(ctx context.Context) {
	producer := arrow_record.NewProducer()
	defer func() {
		if err := producer.Close(); err != nil {
			log.Warnf("probes: arrow producer close: %v", err)
		}
	}()

	for {
		if err := s.runOnce(ctx, producer); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.streamErrs.Add(1)
			log.Warnf("probes: log stream errored, redialling in %s: %v", streamRedialDelay, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(streamRedialDelay):
			}
		}
	}
}

// runOnce opens one bidi stream and processes events on it until it errors
// or the context is cancelled.
func (s *streamer) runOnce(ctx context.Context, producer *arrow_record.Producer) error {
	client := arrowv1.NewArrowLogsServiceClient(s.conn)
	stream, err := client.ArrowLogs(ctx)
	if err != nil {
		return fmt.Errorf("open ArrowLogs stream: %w", err)
	}
	log.Info("probes: opened ArrowLogs stream")

	// Drain server's per-batch BatchStatus replies. We don't act on them in
	// v1 (at-most-once delivery is acceptable) but we must read or the
	// stream's flow control will deadlock.
	recvDone := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				recvDone <- err
				return
			}
		}
	}()

	batch := make([]LogEvent, 0, defaultBatchSize)
	flushTimer := time.NewTimer(defaultBatchAge)
	defer flushTimer.Stop()
	stopFlushTimer(flushTimer)

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		records, err := s.encodeBatch(producer, batch)
		if err != nil {
			return fmt.Errorf("encode batch: %w", err)
		}
		if err := stream.Send(records); err != nil {
			return fmt.Errorf("send batch: %w", err)
		}
		s.batchesSent.Add(1)
		s.eventsSent.Add(uint64(len(batch)))
		batch = batch[:0]
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			_ = flush()
			_ = stream.CloseSend()
			return ctx.Err()

		case err := <-recvDone:
			return fmt.Errorf("stream recv: %w", err)

		case ev, ok := <-s.in:
			if !ok {
				_ = flush()
				_ = stream.CloseSend()
				return nil
			}
			if len(batch) == 0 {
				resetFlushTimer(flushTimer, defaultBatchAge)
			}
			batch = append(batch, ev)
			if len(batch) >= defaultBatchSize {
				if err := flush(); err != nil {
					return err
				}
				stopFlushTimer(flushTimer)
			}

		case <-flushTimer.C:
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

func (s *streamer) encodeBatch(producer *arrow_record.Producer, batch []LogEvent) (*arrowv1.BatchArrowRecords, error) {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	resAttr := rl.Resource().Attributes()
	resAttr.PutStr("service.name", s.opts.ServiceName)
	if s.opts.ServiceVersion != "" {
		resAttr.PutStr("service.version", s.opts.ServiceVersion)
	}
	if s.opts.HostName != "" {
		resAttr.PutStr("host.name", s.opts.HostName)
	}

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("parca-agent/probes")

	records := sl.LogRecords()
	records.EnsureCapacity(len(batch))
	for _, ev := range batch {
		lr := records.AppendEmpty()
		lr.SetTimestamp(pcommon.Timestamp(ev.TimestampNs))
		lr.SetObservedTimestamp(pcommon.Timestamp(ev.ObservedTimestampNs))
		lr.Body().SetStr(ev.ProbeName)
		a := lr.Attributes()
		a.PutInt("pid", int64(ev.PID))
		a.PutInt("tid", int64(ev.TID))
		a.PutStr("comm", ev.Comm)
		a.PutInt("spec_id", int64(ev.SpecID))
	}

	return producer.BatchArrowRecordsFromLogs(logs)
}

// stopFlushTimer drains the timer channel after Stop so the next Reset
// starts cleanly.
func stopFlushTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetFlushTimer(t *time.Timer, d time.Duration) {
	stopFlushTimer(t)
	t.Reset(d)
}
