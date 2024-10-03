package reporter

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/ipc"
	"github.com/apache/arrow/go/v16/arrow/memory"
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
	fname, ftmp, err := o.saveDataToTempFile(ctx)
	if err != nil {
		return err
	}
	if fname == "" {
		return nil
	}

	return os.Rename(ftmp, fname)
}

type accountingWriter struct {
	n int
	w io.WriteSeeker
}

func (a *accountingWriter) Write(p []byte) (n int, err error) {
	n, err = a.w.Write(p)
	a.n += n
	return
}

func (a *accountingWriter) Seek(offset int64, whence int) (int64, error) {
	return a.w.Seek(offset, whence)
}

func (o *OfflineReporter) saveDataToTempFile(ctx context.Context) (string, string, error) {
	id := uuidv7.New()
	fname := filepath.Join(o.dir, id.String()+".ipc")
	ftmp := fname + ".tmp"
	arrowLogger, err := NewArrowLogger(ftmp)
	if err != nil {
		return "", "", err
	}

	n, err := o.writeSamples(ctx, arrowLogger)
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "", nil
	}

	if err := o.writeLocations(ctx, arrowLogger); err != nil {
		return "", "", err
	}

	if err := arrowLogger.Close(); err != nil {
		return "", "", err
	}

	o.stacktraceIDs = make(map[[16]byte]struct{})
	return fname, ftmp, err
}

func (o *OfflineReporter) writeSamples(ctx context.Context, log *ArrowLogger) (int64, error) {
	record := o.pr.buildSampleRecord(ctx)
	if record.NumRows() == 0 {
		return 0, nil
	}
	defer record.Release()

	if err := log.Write(o.pr.mem, record); err != nil {
		return 0, err
	}

	return record.NumRows(), nil
}

func (o *OfflineReporter) writeLocations(ctx context.Context, log *ArrowLogger) error {
	lw := NewLocationsWriter(o.pr.mem)
	stacktraceIDBuilder := array.NewBuilder(o.pr.mem, arrow.BinaryTypes.Binary)
	for k, _ := range o.stacktraceIDs {
		id := [16]byte(k)
		if err := o.pr.buildStacktraceRecordOne(lw, id[:16]); err != nil {
			return err
		}
		stacktraceIDBuilder.(*array.BinaryBuilder).Append(id[:16])
	}

	rec := lw.NewRecord(stacktraceIDBuilder.NewArray())
	if err := log.Write(o.pr.mem, rec); err != nil {
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

type ArrowLogReader struct {
	lastReader    bool
	currentReader *ipc.FileReader
	currentRecord int
	f             *os.File
}

type ArrowLogger struct {
	accountingWriter *accountingWriter
	f                *os.File
}

func NewArrowLogger(name string) (*ArrowLogger, error) {
	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}

	return &ArrowLogger{
		accountingWriter: &accountingWriter{w: f},
		f:                f,
	}, nil
}

func (a *ArrowLogger) Close() error {
	return a.f.Close()
}

func (a *ArrowLogger) Write(mem memory.Allocator, rec arrow.Record) error {
	a.accountingWriter.n = 0
	w, err := ipc.NewFileWriter(a.accountingWriter,
		ipc.WithSchema(rec.Schema()),
		ipc.WithAllocator(mem),
	)
	if err != nil {
		return err
	}

	if err := w.Write(rec); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	// Write the size of the file at the end
	size := make([]byte, 8)
	binary.LittleEndian.PutUint64(size, uint64(a.accountingWriter.n))
	if _, err := a.f.Write(size); err != nil {
		return err
	}

	return nil
}

func OpenArrowLog(fname string) (*ArrowLogReader, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}

	// Seek to the last 8 bytes
	_, err = f.Seek(-8, io.SeekEnd)
	if err != nil {
		return nil, err
	}

	return &ArrowLogReader{
		f: f,
	}, nil
}

func (a *ArrowLogReader) initNextReader() error {
	if a.lastReader {
		return io.EOF
	}

	// Read the last 8 bytes
	size := make([]byte, 8)
	_, err := a.f.Read(size)
	if err != nil {
		return err
	}

	// Read the size of the record
	recordSize := binary.LittleEndian.Uint64(size)

	// Seek to the start of the record
	offset, err := a.f.Seek(-int64(recordSize+8), io.SeekCurrent)
	if err != nil {
		return err
	}

	// We've reached the last record
	if offset == 0 {
		a.lastReader = true
	}

	// Start a new reader
	a.currentReader, err = ipc.NewFileReader(a.f, ipc.WithAllocator(memory.NewGoAllocator()))
	if err != nil {
		return err
	}
	a.currentRecord = 0

	return nil
}

func (a *ArrowLogReader) Next() (arrow.Record, error) {
	if a.currentReader == nil || a.currentRecord == a.currentReader.NumRecords() {
		err := a.initNextReader()
		if err != nil {
			return nil, err
		}
	}

	rec, err := a.currentReader.Record(a.currentRecord)
	if err != nil {
		return nil, err
	}
	a.currentRecord++

	return rec, nil
}
