// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Apache License 2.0.
// See the file "LICENSE" for details.

package reporter

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

// LogEvent is the in-process representation of a single OTLP log record
// produced by any source that uses the ParcaReporter log-event API. The
// streamer batches a slice of these and ships them as Arrow logs.
type LogEvent struct {
	TimestampNs         int64  // wall-clock ns (unix epoch) of the event itself
	ObservedTimestampNs int64  // wall-clock ns at the moment the producer enqueued the event
	Body                string // LogRecord.Body (set as a string body)
	Attributes          map[string]LogAttr
}

// LogAttr is a tagged union covering the OTLP attribute value types we use.
// Producers populate one of Str / Int and leave the other zero. The streamer
// picks the right setter based on which is set.
type LogAttr struct {
	Str    string
	Int    int64
	IsInt  bool
}

const (
	logStreamerBatchSize    = 512
	logStreamerBatchAge     = 250 * time.Millisecond
	logStreamerQueueSize    = 4096
	logStreamerRedialDelay  = 5 * time.Second
	logStreamerResourceScop = "parca-agent"
)

// logStreamerOptions is the resource-attribute payload attached to every batch.
type logStreamerOptions struct {
	ServiceName    string // service.name = "parca-agent"
	ServiceVersion string // service.version = build VCS revision
	HostName       string // host.name = agent --node
}

// logStreamer batches LogEvents and ships them as BatchArrowRecords on the
// ArrowLogsService bidi stream. Owned by arrowReporter; constructed once per
// New() and run in the Start() goroutine when grpcConn is non-nil.
type logStreamer struct {
	conn *grpc.ClientConn
	opts logStreamerOptions

	in chan LogEvent

	// Counters surfaced via prometheus from arrowReporter; the streamer itself
	// only owns the atomics. arrowReporter wires them into a registry.
	batchesSent atomic.Uint64
	eventsSent  atomic.Uint64
	streamErrs  atomic.Uint64
	queueDrops  atomic.Uint64
}

func newLogStreamer(conn *grpc.ClientConn, opts logStreamerOptions) *logStreamer {
	return &logStreamer{
		conn: conn,
		opts: opts,
		in:   make(chan LogEvent, logStreamerQueueSize),
	}
}

// enqueue tries to publish a single event. Returns false if the queue is full;
// the caller (ReportLogEvents) increments queueDrops and moves on.
func (s *logStreamer) enqueue(ev LogEvent) bool {
	select {
	case s.in <- ev:
		return true
	default:
		s.queueDrops.Add(1)
		return false
	}
}

// run batches LogEvents and pushes them on the bidi stream. Reconnects on
// stream error. Returns when ctx is cancelled.
func (s *logStreamer) run(ctx context.Context) {
	producer := arrow_record.NewProducer()
	defer func() {
		if err := producer.Close(); err != nil {
			log.Warnf("log streamer: arrow producer close: %v", err)
		}
	}()

	for {
		if err := s.runOnce(ctx, producer); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.streamErrs.Add(1)
			log.Warnf("log streamer: bidi stream errored, redialling in %s: %v", logStreamerRedialDelay, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(logStreamerRedialDelay):
			}
		}
	}
}

// runOnce opens one bidi stream and processes events on it until it errors or
// the context is cancelled.
func (s *logStreamer) runOnce(ctx context.Context, producer *arrow_record.Producer) error {
	client := arrowv1.NewArrowLogsServiceClient(s.conn)
	stream, err := client.ArrowLogs(ctx)
	if err != nil {
		return fmt.Errorf("open ArrowLogs stream: %w", err)
	}
	log.Info("log streamer: opened ArrowLogs stream")

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

	batch := make([]LogEvent, 0, logStreamerBatchSize)
	flushTimer := time.NewTimer(logStreamerBatchAge)
	defer flushTimer.Stop()
	stopLogFlushTimer(flushTimer)

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
				resetLogFlushTimer(flushTimer, logStreamerBatchAge)
			}
			batch = append(batch, ev)
			if len(batch) >= logStreamerBatchSize {
				if err := flush(); err != nil {
					return err
				}
				stopLogFlushTimer(flushTimer)
			}

		case <-flushTimer.C:
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

func (s *logStreamer) encodeBatch(producer *arrow_record.Producer, batch []LogEvent) (*arrowv1.BatchArrowRecords, error) {
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
	sl.Scope().SetName(logStreamerResourceScop)

	records := sl.LogRecords()
	records.EnsureCapacity(len(batch))
	for _, ev := range batch {
		lr := records.AppendEmpty()
		lr.SetTimestamp(pcommon.Timestamp(ev.TimestampNs))
		lr.SetObservedTimestamp(pcommon.Timestamp(ev.ObservedTimestampNs))
		lr.Body().SetStr(ev.Body)
		a := lr.Attributes()
		for k, v := range ev.Attributes {
			if v.IsInt {
				a.PutInt(k, v.Int)
			} else {
				a.PutStr(k, v.Str)
			}
		}
	}

	return producer.BatchArrowRecordsFromLogs(logs)
}

// stopLogFlushTimer drains the timer channel after Stop so the next Reset
// starts cleanly.
func stopLogFlushTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetLogFlushTimer(t *time.Timer, d time.Duration) {
	stopLogFlushTimer(t)
	t.Reset(d)
}
