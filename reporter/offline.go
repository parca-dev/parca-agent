package reporter

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/apache/arrow/go/v14/arrow/memory"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/ipc"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"
	"github.com/parca-dev/parca-agent/flags"
	"github.com/samborkent/uuidv7"
	log "github.com/sirupsen/logrus"
)

type OfflineReporter struct {
	pr            *ParcaReporter
	dir           string
	stacktraceIDs map[[16]byte]struct{}
}

var _ reporter.Reporter = &OfflineReporter{}

func NewOfflineReporter(dir string, f flags.Flags, traceHandlerCacheSize uint32, vcs string) (*OfflineReporter, error) {
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return nil, err
	}
	pr, err := New(
		memory.DefaultAllocator,
		nil,
		nil,
		Labels{},
		f.Profiling.Duration,
		f.Debuginfo.Strip,
		f.Debuginfo.UploadMaxParallel,
		f.Debuginfo.UploadDisable,
		int64(f.Profiling.CPUSamplingFrequency),
		traceHandlerCacheSize,
		f.Debuginfo.UploadQueueSize,
		f.Debuginfo.TempDir,
		f.Node,
		nil,
		vcs,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return &OfflineReporter{
		dir:           dir,
		pr:            pr,
		stacktraceIDs: make(map[[16]byte]struct{}),
	}, nil
}

func (o *OfflineReporter) Run(ctx context.Context) {
	reportInterval := 10 * time.Second
	go func() {
		tick := time.NewTicker(reportInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-o.pr.stopSignal:
				return
			case <-tick.C:
				if err := o.saveDataToFile(ctx); err != nil {
					// TODO: make fatal?
					log.Errorf("Save data failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(reportInterval, 0.2))
			}
		}
	}()
}

func (o *OfflineReporter) Stop() {
	o.pr.Stop()
}

func (o *OfflineReporter) saveDataToFile(ctx context.Context) error {
	id := uuidv7.New()
	fname := filepath.Join(o.dir, id.String()+".ipc")
	ftmp := fname + ".tmp"

	f, err := os.Create(ftmp)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	n, err := o.writeSamples(ctx, buf)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}

	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}

	buf.Reset()
	if err := o.writeLocations(ctx, buf); err != nil {
		return err
	}

	o.stacktraceIDs = make(map[[16]byte]struct{})

	_, err = f.Write(buf.Bytes())
	if err != nil {
		return err
	}

	if err := os.Rename(ftmp, fname); err != nil {
		return err
	}

	return err
}

func (o *OfflineReporter) writeSamples(ctx context.Context, buf *bytes.Buffer) (int64, error) {
	record := o.pr.buildSampleRecord(ctx)
	if record.NumRows() == 0 {
		return 0, nil
	}
	defer record.Release()

	w := ipc.NewWriter(buf,
		ipc.WithSchema(record.Schema()),
		ipc.WithAllocator(o.pr.mem),
	)

	if err := w.Write(record); err != nil {
		return 0, err
	}

	if err := w.Close(); err != nil {
		return 0, err
	}

	return record.NumRows(), nil
}

func (o *OfflineReporter) writeLocations(ctx context.Context, buf *bytes.Buffer) error {
	lw := NewLocationsWriter(o.pr.mem)
	stacktraceIDBuilder := array.NewBuilder(o.pr.mem, StacktraceIDField.Type)
	for k, _ := range o.stacktraceIDs {
		id := [16]byte(k)
		if err := o.pr.buildStacktraceRecordOne(lw, id[:16]); err != nil {
			return err
		}
		stacktraceIDBuilder.(*array.BinaryBuilder).Append(id[:16])
	}

	rec := lw.NewRecord(stacktraceIDBuilder.NewArray())

	w := ipc.NewWriter(buf,
		ipc.WithSchema(rec.Schema()),
		ipc.WithAllocator(o.pr.mem),
	)

	if err := w.Write(rec); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	return nil
}

// ReportTraceEvent accepts a trace event (trace metadata with frames and counts)
// and caches it for reporting to the backend. It returns true if the event was
// enqueued for reporting, and false if the event was ignored.
func (o *OfflineReporter) ReportTraceEvent(trace *libpf.Trace, meta *reporter.TraceEventMeta) {
	labelsRR := o.pr.labelsForTID(meta.TID, meta.PID, meta.Comm)

	if !labelsRR.keep {
		log.Debugf("Skipping trace event for PID %d, as it was filtered out by relabeling", meta.PID)
		return
	}
	o.pr.sampleWriterMu.Lock()
	defer o.pr.sampleWriterMu.Unlock()

	o.pr.reportTraceEventLocked(trace, meta, labelsRR)

	buf := [16]byte{}
	trace.Hash.PutBytes16(&buf)
	o.stacktraceIDs[buf] = struct{}{}
}

// ReportFramesForTrace accepts a trace with the corresponding frames
// and caches this information before a periodic reporting to the backend.
func (o *OfflineReporter) ReportFramesForTrace(trace *libpf.Trace) {
	panic("not implemented") // TODO: Implement
}

// ReportCountForTrace accepts a hash of a trace with a corresponding count and
// caches this information before a periodic reporting to the backend.
func (o *OfflineReporter) ReportCountForTrace(traceHash libpf.TraceHash, count uint16, meta *reporter.TraceEventMeta) {
	panic("not implemented") // TODO: Implement
}

// SupportsReportTraceEvent returns true if the reporter supports reporting trace events
// via ReportTraceEvent().
func (o *OfflineReporter) SupportsReportTraceEvent() bool {
	return true
}

// ReportFallbackSymbol enqueues a fallback symbol for reporting, for a given frame.
func (o *OfflineReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	o.pr.ReportFallbackSymbol(frameID, symbol)
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information before a periodic reporting to the backend.
//
// The `open` argument can be used to open the executable for reading. Interpreters
// that don't support this may pass a `nil` function pointer. Implementations that
// wish to upload executables should NOT block this function to do so and instead just
// open the file and then enqueue the upload in the background.
func (o *OfflineReporter) ExecutableMetadata(fileID libpf.FileID, fileName string, buildID string, interp libpf.InterpreterType, open reporter.ExecutableOpener) {
}

// FrameMetadata accepts metadata associated with a frame and caches this information before
// a periodic reporting to the backend.
func (o *OfflineReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno, lineNumber util.SourceLineno, functionOffset uint32, functionName string, filePath string) {
	panic("not implemented") // TODO: Implement
}

// ReportHostMetadata enqueues host metadata for sending (to the collection agent).
func (o *OfflineReporter) ReportHostMetadata(metadataMap map[string]string) {
	panic("not implemented") // TODO: Implement
}

// ReportHostMetadataBlocking sends host metadata to the collection agent.
func (o *OfflineReporter) ReportHostMetadataBlocking(ctx context.Context, metadataMap map[string]string, maxRetries int, waitRetry time.Duration) error {
	panic("not implemented") // TODO: Implement
}

// ReportMetrics accepts an id with a corresponding value and caches this
// information before a periodic reporting to the backend.
func (o *OfflineReporter) ReportMetrics(timestamp uint32, ids []uint32, values []int64) {
	panic("not implemented") // TODO: Implement
}

func (o *OfflineReporter) GetMetrics() reporter.Metrics {
	panic("not implemented") // TODO: Implement
}
