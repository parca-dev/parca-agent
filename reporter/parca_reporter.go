/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	debuginfogrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/debuginfo/v1alpha1/debuginfov1alpha1grpc"
	profilestoregrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	profilestorepb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/profilestore/v1alpha1"
	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/ipc"
	"github.com/apache/arrow/go/v16/arrow/memory"
	lru "github.com/elastic/go-freelru"
	"github.com/parca-dev/parca-agent/metrics"
	"github.com/parca-dev/parca-agent/reporter/metadata"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	log "github.com/sirupsen/logrus"
	"github.com/xyproto/ainur"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	otelmetrics "go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// Assert that we implement the full Reporter interface.
var _ reporter.Reporter = (*ParcaReporter)(nil)

// processInfo stores metadata about the process.
type processInfo struct {
	comm           string
	mainExecutable libpf.FileID
}

// labelRetrievalResult is a result of a label retrieval.
type labelRetrievalResult struct {
	labels labels.Labels
	keep   bool
}

// sourceInfo allows to map a frame to its source origin.
type sourceInfo struct {
	lineNumber     libpf.SourceLineno
	functionOffset uint32
	functionName   string
	filePath       string
}

// stack is a collection of frames.
type stack struct {
	files      []libpf.FileID
	linenos    []libpf.AddressOrLineno
	frameTypes []libpf.FrameType
}

// ParcaReporter receives and transforms information to be OTLP/profiles compliant.
type ParcaReporter struct {
	// client for the connection to the receiver.
	client profilestoregrpc.ProfileStoreServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// To fill in the profiles signal with the relevant information,
	// this structure holds in long-term storage information that might
	// be duplicated in other places but not accessible for ParcaReporter.

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]

	// labels stores labels about the thread.
	labels *lru.SyncedLRU[libpf.PID, labelRetrievalResult]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

	// samples stores the so far received samples.
	sampleWriter   *SampleWriter
	sampleWriterMu sync.Mutex

	// stacks stores known stacks.
	stacks *lru.SyncedLRU[libpf.TraceHash, stack]

	// uploader uploads debuginfo to the backend.
	uploader *ParcaSymbolUploader

	// the apache arrow allocator to use.
	mem memory.Allocator

	// additional labels to attach to all profiling data.
	externalLabels []Label

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int64

	// disableSymbolUpload disables the symbol upload.
	disableSymbolUpload bool

	// reportInterval is the interval at which to report data.
	reportInterval time.Duration

	// relabelConfigs are the relabel configurations to apply to the labels.
	relabelConfigs []*relabel.Config

	// node name
	nodeName string

	// metadata providers
	metadataProviders []metadata.MetadataProvider

	// Prometheus metrics registry
	reg prometheus.Registerer

	// Metrics that we have seen via ReportMetrics
	otelLibraryMetrics map[string]prometheus.Metric

	// Our own metrics
	sampleWriteRequestBytes     prometheus.Counter
	stacktraceWriteRequestBytes prometheus.Counter
}

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

func (r *ParcaReporter) SupportsReportTraceEvent() bool { return true }

// ReportTraceEvent enqueues reported trace events for the OTLP reporter.
func (r *ParcaReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *reporter.TraceEventMeta) {

	// This is an LRU so we need to check every time if the stack is already
	// known, as it might have been evicted.
	if _, exists := r.stacks.Get(trace.Hash); !exists {
		r.stacks.Add(trace.Hash, stack{
			files:      trace.Files,
			linenos:    trace.Linenos,
			frameTypes: trace.FrameTypes,
		})
	}

	labelRetrievalResult := r.labelsForTID(meta.TID, meta.PID, meta.Comm)

	if !labelRetrievalResult.keep {
		log.Debugf("Skipping trace event for PID %d, as it was filtered out by relabeling", meta.PID)
		return
	}

	r.sampleWriterMu.Lock()
	defer r.sampleWriterMu.Unlock()

	for _, lbl := range labelRetrievalResult.labels {
		r.sampleWriter.Label(lbl.Name).AppendString(lbl.Value)
	}

	for k, v := range trace.CustomLabels {
		r.sampleWriter.Label(k).AppendString(v)
	}

	buf := [16]byte{}
	trace.Hash.PutBytes16(&buf)
	r.sampleWriter.StacktraceID.Append(buf[:])

	r.sampleWriter.Value.Append(1)
	r.sampleWriter.Timestamp.Append(int64(meta.Timestamp))
}

func (r *ParcaReporter) addMetadataForPID(pid libpf.PID, lb *labels.Builder) bool {
	cache := true

	for _, p := range r.metadataProviders {
		cacheable := p.AddMetadata(pid, lb)
		cache = cache && cacheable
	}

	return cache
}

func (r *ParcaReporter) labelsForTID(tid, pid libpf.PID, comm string) labelRetrievalResult {
	if labels, exists := r.labels.Get(tid); exists {
		return labels
	}

	lb := &labels.Builder{}
	lb.Set("node", r.nodeName)
	lb.Set("__meta_thread_comm", comm)
	lb.Set("__meta_thread_id", fmt.Sprint(tid))
	cacheable := r.addMetadataForPID(pid, lb)

	keep := relabel.ProcessBuilder(lb, r.relabelConfigs...)

	// Meta labels are deleted after relabelling. Other internal labels propagate to
	// the target which decides whether they will be part of their label set.
	lb.Range(func(l labels.Label) {
		if strings.HasPrefix(l.Name, model.MetaLabelPrefix) {
			lb.Del(l.Name)
		}
	})

	res := labelRetrievalResult{
		labels: lb.Labels(),
		keep:   keep,
	}

	if cacheable {
		r.labels.Add(tid, res)
	}
	return res
}

// ReportFramesForTrace is a NOP for ParcaReporter.
func (r *ParcaReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for ParcaReporter.
func (r *ParcaReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *reporter.TraceEventMeta) {
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *ParcaReporter) ExecutableMetadata(args *reporter.ExecutableMetadataArgs) {

	if args.Interp != libpf.Native {
		r.executables.Add(args.FileID, metadata.ExecInfo{
			FileName: args.FileName,
			BuildID:  args.GnuBuildID,
		})
		return
	}

	// Always attempt to upload, the uploader is responsible for deduplication.
	r.uploader.Upload(context.TODO(), args.FileID, args.GnuBuildID, args.Open)

	if _, exists := r.executables.Get(args.FileID); exists {
		return
	}

	f, err := args.Open()
	if err != nil {
		log.Debugf("Failed to open file %s: %v", args.FileName, err)
		return
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		log.Debugf("Failed to open ELF file %s: %v", args.FileName, err)
		return
	}

	r.executables.Add(args.FileID, metadata.ExecInfo{
		FileName: args.FileName,
		BuildID:  args.GnuBuildID,
		Compiler: ainur.Compiler(ef),
		Static:   ainur.Static(ef),
		Stripped: ainur.Stripped(ef),
	})
}

// FrameKnown returns whether we have already determined the metadata for
// a given frame.
func (r *ParcaReporter) FrameKnown(id libpf.FrameID) bool {
	if frameMapLock, exists := r.frames.Get(id.FileID()); exists {
		l := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&l)
		_, exists := (*l)[id.AddressOrLine()]
		return exists
	}
	return false
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *ParcaReporter) FrameMetadata(args *reporter.FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()
	sourceFile := args.SourceFile

	if frameMapLock, exists := r.frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		if sourceFile == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				sourceFile = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
			lineNumber:     args.SourceLine,
			functionOffset: args.FunctionOffset,
			functionName:   args.FunctionName,
			filePath:       sourceFile,
		}

		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     args.SourceLine,
		functionOffset: args.FunctionOffset,
		functionName:   args.FunctionName,
		filePath:       sourceFile,
	}
	mu := xsync.NewRWMutex(v)
	r.frames.Add(fileID, &mu)
}

// ReportHostMetadata enqueues host metadata.
func (r *ParcaReporter) ReportHostMetadata(metadataMap map[string]string) {
	// noop
}

// ReportHostMetadataBlocking enqueues host metadata.
func (r *ParcaReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	// noop
	return nil
}

// ReportMetrics records metrics.
func (r *ParcaReporter) ReportMetrics(_ uint32, ids []uint32, values []int64) {
	for i := 0; i < len(ids) && i < len(values); i++ {
		id := ids[i]
		val := values[i]
		field, ok := metrics.AllMetrics[otelmetrics.MetricID(id)]
		if !ok {
			log.Warnf("Unknown metric ID: %d", id)
			continue
		}
		f := strings.Replace(field.Field, ".", "_", -1)
		m, ok := r.otelLibraryMetrics[f]
		if !ok {
			switch field.Type {
			case metrics.MetricTypeGauge:
				g := prometheus.NewGauge(prometheus.GaugeOpts{
					Name: f,
					Help: field.Desc,
				})
				r.reg.MustRegister(g)
				m = g
			case metrics.MetricTypeCounter:
				c := prometheus.NewCounter(prometheus.CounterOpts{
					Name: f,
					Help: field.Desc,
				})
				r.reg.MustRegister(c)
				m = c

			default:
				log.Warnf("Unknown metric type: %d", field.Type)
				continue
			}
			r.otelLibraryMetrics[f] = m
		}
		if counter, ok := m.(prometheus.Counter); ok {
			counter.Add(float64(val))
		} else if gauge, ok := m.(prometheus.Gauge); ok {
			gauge.Set(float64(val))
		} else {
			log.Errorf("Bad metric type (this should never happen): %v", m)
		}
	}
}

// Stop triggers a graceful shutdown of ParcaReporter.
func (r *ParcaReporter) Stop() {
	close(r.stopSignal)
}

// GetMetrics returns internal metrics of ParcaReporter.
func (r *ParcaReporter) GetMetrics() reporter.Metrics {
	// noop
	return reporter.Metrics{}
}

type Label struct {
	Name  string
	Value string
}

type Labels []Label

func (l Labels) String() string {
	var buf bytes.Buffer
	for i, label := range l {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(label.Name)
		buf.WriteString("=")
		buf.WriteString(label.Value)
	}
	return buf.String()
}

// New creates a ParcaReporter.
func New(
	mem memory.Allocator,
	client profilestoregrpc.ProfileStoreServiceClient,
	debuginfoClient debuginfogrpc.DebuginfoServiceClient,
	externalLabels []Label,
	reportInterval time.Duration,
	stripTextSection bool,
	symbolUploadConcurrency int,
	disableSymbolUpload bool,
	samplesPerSecond int64,
	cacheSize uint32,
	uploaderQueueSize uint32,
	cacheDir string,
	nodeName string,
	relabelConfigs []*relabel.Config,
	agentRevision string,
	reg prometheus.Registerer,
) (*ParcaReporter, error) {
	executables, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	labels, err := lru.NewSynced[libpf.PID, labelRetrievalResult](cacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}

	stacks, err := lru.NewSynced[libpf.TraceHash, stack](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	cmp, err := metadata.NewContainerMetadataProvider(context.TODO(), nodeName)
	if err != nil {
		return nil, err
	}

	sysMeta, err := metadata.NewSystemMetadataProvider()
	if err != nil {
		return nil, err
	}

	sampleWriteRequestBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sample_write_request_bytes",
		Help: "the total number of bytes written in WriteRequest calls for sample records",
	})
	stacktraceWriteRequestBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "stacktrace_write_request_bytes",
		Help: "the total number of bytes written in WriteRequest calls for stacktrace records",
	})

	reg.MustRegister(sampleWriteRequestBytes)
	reg.MustRegister(stacktraceWriteRequestBytes)

	r := &ParcaReporter{
		stopSignal:          make(chan libpf.Void),
		client:              nil,
		executables:         executables,
		labels:              labels,
		frames:              frames,
		sampleWriter:        NewSampleWriter(mem),
		stacks:              stacks,
		mem:                 mem,
		externalLabels:      externalLabels,
		samplesPerSecond:    samplesPerSecond,
		disableSymbolUpload: disableSymbolUpload,
		reportInterval:      reportInterval,
		nodeName:            nodeName,
		relabelConfigs:      relabelConfigs,
		metadataProviders: []metadata.MetadataProvider{
			metadata.NewProcessMetadataProvider(),
			metadata.NewMainExecutableMetadataProvider(executables),
			metadata.NewAgentMetadataProvider(agentRevision),
			cmp,
			sysMeta,
		},
		reg:                         reg,
		otelLibraryMetrics:          make(map[string]prometheus.Metric),
		sampleWriteRequestBytes:     sampleWriteRequestBytes,
		stacktraceWriteRequestBytes: stacktraceWriteRequestBytes,
	}

	r.client = client

	if !disableSymbolUpload {
		u, err := NewParcaSymbolUploader(
			debuginfoClient,
			cacheSize,
			stripTextSection,
			uploaderQueueSize,
			symbolUploadConcurrency,
			cacheDir,
		)
		if err != nil {
			close(r.stopSignal)
			return nil, err
		}
		r.uploader = u
	}

	return r, nil
}

func (r *ParcaReporter) Run(mainCtx context.Context) (reporter.Reporter, error) {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	if !r.disableSymbolUpload {
		go func() {
			if err := r.uploader.Run(ctx); err != nil {
				log.Fatalf("Running symbol uploader failed: %v", err)
			}
		}()
	}

	go func() {
		tick := time.NewTicker(r.reportInterval)
		buf := bytes.NewBuffer(nil)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportDataToBackend(ctx, buf); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(r.reportInterval, 0.2))
			}
		}
	}()

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	go func() {
		<-r.stopSignal
		cancelReporting()
	}()

	return r, nil
}

// reportDataToBackend creates and sends out an arrow record for a Parca backend.
func (r *ParcaReporter) reportDataToBackend(ctx context.Context, buf *bytes.Buffer) error {
	record := r.buildSampleRecord(ctx)
	defer record.Release()

	if record.NumRows() == 0 {
		log.Debugf("Skip sending of profile with no samples")
		return nil
	}

	buf.Reset()
	w := ipc.NewWriter(buf,
		ipc.WithSchema(record.Schema()),
		ipc.WithAllocator(r.mem),
	)

	if err := w.Write(record); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	client, err := r.client.Write(ctx)
	if err != nil {
		return err
	}

	if err := client.Send(&profilestorepb.WriteRequest{
		Record: buf.Bytes(),
	}); err != nil {
		return err
	}
	r.sampleWriteRequestBytes.Add(float64(buf.Len()))

	log.Debugf("Sent profile with %d samples", record.NumRows())

	resp, err := client.Recv()
	if err != nil && err != io.EOF {
		return err
	}
	if len(resp.Record) == 0 || err == io.EOF {
		// The backend didn't want any more information.
		return nil
	}

	// If we end up here the backend requested the agent to resolve stacktrace
	// IDs and send a record with the full stacktraces.
	reader, err := ipc.NewReader(
		bytes.NewReader(resp.Record),
		ipc.WithAllocator(r.mem),
	)
	if err != nil {
		return err
	}
	defer reader.Release()

	if !reader.Next() {
		return errors.New("arrow/ipc: could not read record from stream")
	}

	if reader.Err() != nil {
		return reader.Err()
	}

	rec := reader.Record()
	defer rec.Release()

	fields := rec.Schema().Fields()
	if len(fields) != 1 {
		return fmt.Errorf("arrow/ipc: invalid number of fields in record (got=%d, want=1)", len(fields))
	}

	if fields[0].Name != "stacktrace_id" {
		return fmt.Errorf("arrow/ipc: invalid field name in record (got=%s, want=stacktrace_id)", fields[0].Name)
	}

	stacktraceIDs, ok := rec.Column(0).(*array.Binary)
	if !ok {
		return fmt.Errorf("arrow/ipc: invalid column type in record (got=%T, want=*array.Binary)", rec.Column(0))
	}

	rec, err = r.buildStacktraceRecord(ctx, stacktraceIDs)

	if err != nil {
		return err
	}

	buf.Reset()
	w = ipc.NewWriter(buf,
		ipc.WithSchema(rec.Schema()),
		ipc.WithAllocator(r.mem),
	)

	if err := w.Write(rec); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	log.Debugf("Sent stacktrace record with %d stacktraces", rec.NumRows())

	if err := client.Send(&profilestorepb.WriteRequest{
		Record: buf.Bytes(),
	}); err != nil {
		return err
	}
	r.stacktraceWriteRequestBytes.Add(float64(buf.Len()))

	return client.CloseSend()
}

func (r *ParcaReporter) writeCommonLabels(w *SampleWriter, rows uint64) {
	for _, label := range r.externalLabels {
		w.LabelAll(label.Name, label.Value)
	}
}

// buildSampleRecord returns an apache arrow record containing all collected
// samples up to this moment. It does not contain the full stacktraces, only
// the stacktrace IDs, depending on whether the backend already knows the
// stacktrace ID, it might request the full stacktrace from the agent. The
// second return value contains all the raw samples, which can be used to
// resolve the stacktraces.
func (r *ParcaReporter) buildSampleRecord(ctx context.Context) arrow.Record {
	newWriter := NewSampleWriter(r.mem)

	r.sampleWriterMu.Lock()
	w := r.sampleWriter
	r.sampleWriter = newWriter
	r.sampleWriterMu.Unlock()

	defer w.Release()

	// Completing the record with all values that are the same for all rows.
	rows := uint64(w.Value.Len())
	r.writeCommonLabels(w, rows)
	w.Producer.ree.Append(rows)
	w.Producer.bd.AppendString("parca_agent")
	w.SampleType.ree.Append(rows)
	w.SampleType.bd.AppendString("samples")
	w.SampleUnit.ree.Append(rows)
	w.SampleUnit.bd.AppendString("count")
	w.PeriodType.ree.Append(rows)
	w.PeriodType.bd.AppendString("cpu")
	w.PeriodUnit.ree.Append(rows)
	w.PeriodUnit.bd.AppendString("nanoseconds")
	w.Temporality.ree.Append(rows)
	w.Temporality.bd.AppendString("delta")
	w.Period.ree.Append(rows)
	// Since the period is of type cpu nanoseconds it is the time between
	// samples.
	w.Period.ib.Append(1e9 / int64(r.samplesPerSecond))
	w.Duration.ree.Append(rows)
	w.Duration.ib.Append(time.Second.Nanoseconds())

	return w.NewRecord()
}

func (r *ParcaReporter) buildStacktraceRecord(ctx context.Context, stacktraceIDs *array.Binary) (arrow.Record, error) {
	w := NewLocationsWriter(r.mem)
	for i := 0; i < stacktraceIDs.Len(); i++ {
		isComplete := true

		traceHash, err := libpf.TraceHashFromBytes(stacktraceIDs.Value(i))
		if err != nil {
			return nil, err
		}

		traceInfo, exists := r.stacks.Get(traceHash)
		if !exists {
			w.LocationsList.Append(false)
			w.IsComplete.Append(false)
			continue
		}

		// Walk every frame of the trace.
		if len(traceInfo.frameTypes) == 0 {
			w.LocationsList.Append(false)
		} else {
			w.LocationsList.Append(true)
		}
		for i := range traceInfo.frameTypes {
			w.Locations.Append(true)
			w.Address.Append(uint64(traceInfo.linenos[i]))
			w.FrameType.AppendString(traceInfo.frameTypes[i].String())

			switch frameKind := traceInfo.frameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				execInfo, exists := r.executables.Get(traceInfo.files[i])

				if exists {
					w.MappingFile.AppendString(execInfo.FileName)

					if execInfo.BuildID != "" {
						w.MappingBuildID.AppendString(execInfo.BuildID)
					} else {
						w.MappingBuildID.AppendString(traceInfo.files[i].StringNoQuotes())
					}
				} else {
					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					w.MappingFile.AppendString("UNKNOWN")
					w.MappingBuildID.AppendNull()
					isComplete = false
				}
				w.Lines.Append(false)
			case libpf.KernelFrame:
				f := traceInfo.files[i]
				execInfo, exists := r.executables.Get(f)
				var moduleName string
				if exists {
					moduleName = execInfo.FileName
				} else {
					moduleName = "vmlinux"
				}

				var symbol string
				var lineNumber int64
				fileIDInfoLock, exists := r.frames.Get(f)
				if !exists {
					// TODO: choose a proper default value if the kernel symbol was not
					// reported yet.
					symbol = "UNKNOWN"
					isComplete = false
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					si, exists := (*fileIDInfo)[traceInfo.linenos[i]]
					if exists {
						lineNumber = int64(si.lineNumber)
						symbol = si.functionName
						// To match historical practice,
						// we put "[kernel.kallsyms]" as the mapping file,
						// "vmlinux" the module name as the function filename,
						// and do nothing with the actual filePath.
						//
						// TODO: Think about this. Should we reconsider this and actually report the file path?
						//
						// filePath = si.filePath
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}
				w.MappingBuildID.AppendNull()
				w.FunctionFilename.AppendString(moduleName)
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(lineNumber)
				w.FunctionName.AppendString(symbol)
				w.FunctionSystemName.AppendString("")
				w.MappingFile.AppendString("[kernel.kallsyms]")
				w.FunctionStartLine.Append(int64(0))
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
				w.MappingFile.AppendString("agent-internal-error-frame")
				w.MappingBuildID.AppendNull()
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(int64(0))
				w.FunctionName.AppendString("aborted")
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendNull()
				w.FunctionStartLine.Append(int64(0))
			default:
				var (
					lineNumber   int64
					functionName string
					filePath     string
				)

				fileIDInfoLock, exists := r.frames.Get(traceInfo.files[i])
				if !exists {
					// At this point, we do not have enough information for the
					// frame. Therefore, we report a dummy entry and use the
					// interpreter as filename.
					functionName = "UNREPORTED"
					filePath = "UNREPORTED"
					isComplete = false
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					si, exists := (*fileIDInfo)[traceInfo.linenos[i]]
					if !exists {
						// At this point, we do not have enough information for
						// the frame. Therefore, we report a dummy entry and
						// use the interpreter as filename. To differentiate
						// this case with the case where no information about
						// the file ID is available at all, we use a different
						// name for reported function.
						functionName = "UNRESOLVED"
						filePath = "UNRESOLVED"
						isComplete = false
					} else {
						lineNumber = int64(si.lineNumber)
						functionName = si.functionName
						filePath = si.filePath
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}
				// empty path causes the backend to crash
				if filePath == "" {
					filePath = "UNKNOWN"
				}
				w.MappingFile.AppendString(frameKind.String())
				w.MappingBuildID.AppendNull()
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(lineNumber)
				w.FunctionName.AppendString(functionName)
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendString(filePath)
				w.FunctionStartLine.Append(int64(0))
			}
		}

		w.IsComplete.Append(isComplete)
	}

	return w.NewRecord(stacktraceIDs), nil
}
