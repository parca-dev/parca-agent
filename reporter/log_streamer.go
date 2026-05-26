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

package reporter

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
)

// LogEvent is the in-process representation of a single OTLP log record
// produced by any source that uses the ParcaReporter log-event API. The
// streamer batches a slice of these and ships them as one OTLP/gRPC
// ExportLogsServiceRequest.
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
	Str   string
	Int   int64
	IsInt bool
}

const (
	logStreamerBatchSize    = 512
	logStreamerBatchAge     = 250 * time.Millisecond
	logStreamerQueueSize    = 4096
	logStreamerErrorBackoff = 5 * time.Second
	logStreamerScopeName    = "parca-agent"
)

// logStreamerOptions is the resource-attribute payload attached to every batch.
type logStreamerOptions struct {
	ServiceName    string // service.name = "parca-agent"
	ServiceVersion string // service.version = build VCS revision
	HostName       string // host.name = agent --node
}

// logStreamer batches LogEvents and ships them as OTLP/gRPC
// ExportLogsServiceRequest messages via plogotlp.GRPCClient. Owned by
// arrowReporter; constructed once per New() and run in the Start() goroutine
// when grpcConn is non-nil.
type logStreamer struct {
	conn   *grpc.ClientConn
	client plogotlp.GRPCClient
	opts   logStreamerOptions

	in chan LogEvent

	// Counters surfaced via prometheus from arrowReporter; the streamer itself
	// only owns the atomics. arrowReporter wires them into a registry.
	batchesSent atomic.Uint64
	eventsSent  atomic.Uint64
	exportErrs  atomic.Uint64
	queueDrops  atomic.Uint64
	rejected    atomic.Uint64
}

func newLogStreamer(conn *grpc.ClientConn, opts logStreamerOptions) *logStreamer {
	return &logStreamer{
		conn:   conn,
		client: plogotlp.NewGRPCClient(conn),
		opts:   opts,
		in:     make(chan LogEvent, logStreamerQueueSize),
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

// run batches LogEvents and ships them as OTLP ExportLogsServiceRequest
// messages. Each batch is one unary RPC; transient backend errors trigger a
// brief sleep to avoid hot-looping on persistent failures. Returns when ctx is
// cancelled.
func (s *logStreamer) run(ctx context.Context) {
	batch := make([]LogEvent, 0, logStreamerBatchSize)
	flushTimer := time.NewTimer(logStreamerBatchAge)
	defer flushTimer.Stop()
	stopLogFlushTimer(flushTimer)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.export(ctx, batch); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.exportErrs.Add(1)
			log.Warnf("log streamer: export errored (dropping %d events, backing off %s): %v",
				len(batch), logStreamerErrorBackoff, err)
			// Backoff to avoid spinning on a persistently-broken endpoint.
			// Events accumulating during the sleep are queued in s.in and may
			// also be dropped by enqueue's non-blocking send (queueDrops).
			select {
			case <-ctx.Done():
			case <-time.After(logStreamerErrorBackoff):
			}
		} else {
			s.batchesSent.Add(1)
			s.eventsSent.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return

		case ev, ok := <-s.in:
			if !ok {
				flush()
				return
			}
			if len(batch) == 0 {
				resetLogFlushTimer(flushTimer, logStreamerBatchAge)
			}
			batch = append(batch, ev)
			if len(batch) >= logStreamerBatchSize {
				flush()
				stopLogFlushTimer(flushTimer)
			}

		case <-flushTimer.C:
			flush()
		}
	}
}

// export ships one batch as a single OTLP/gRPC ExportLogsServiceRequest. The
// returned error means the RPC itself failed; a successful RPC with
// PartialSuccess.RejectedLogRecords > 0 is logged but not returned (the rest of
// the batch was accepted).
func (s *logStreamer) export(ctx context.Context, batch []LogEvent) error {
	req := plogotlp.NewExportRequestFromLogs(s.buildLogs(batch))
	resp, err := s.client.Export(ctx, req)
	if err != nil {
		return fmt.Errorf("plogotlp export: %w", err)
	}
	if ps := resp.PartialSuccess(); ps.RejectedLogRecords() > 0 {
		s.rejected.Add(uint64(ps.RejectedLogRecords()))
		log.Warnf("log streamer: server rejected %d/%d records: %s",
			ps.RejectedLogRecords(), len(batch), ps.ErrorMessage())
	}
	return nil
}

func (s *logStreamer) buildLogs(batch []LogEvent) plog.Logs {
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
	sl.Scope().SetName(logStreamerScopeName)

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

	return logs
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
