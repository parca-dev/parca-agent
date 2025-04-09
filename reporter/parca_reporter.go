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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
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
	"github.com/klauspost/compress/zstd"
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
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
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

	offlineModeConfig *OfflineModeConfig

	// Protects the log file,
	// which is accessed from both the main reporter loop
	// and the rotator
	offlineModeLogMu sync.Mutex

	offlineModeLogFile *os.File
	offlineModeLogPath string

	offlineModeNBatchesInCurrentFile uint16

	// Set of stacks that are already in the current log,
	// meaning we don't need to log them again.
	offlineModeLoggedStacks *lru.SyncedLRU[libpf.TraceHash, struct{}]
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
	meta *samples.TraceEventMeta) error {

	// This is an LRU so we need to check every time if the stack is already
	// known, as it might have been evicted.
	if _, exists := r.stacks.Get(trace.Hash); !exists {
		r.stacks.Add(trace.Hash, stack{
			files:      trace.Files,
			linenos:    trace.Linenos,
			frameTypes: trace.FrameTypes,
		})
	}

	labelRetrievalResult := r.labelsForTID(meta.TID, meta.PID, meta.Comm, meta.CPU)

	if !labelRetrievalResult.keep {
		log.Debugf("Skipping trace event for PID %d, as it was filtered out by relabeling", meta.PID)
		return nil
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

	r.sampleWriter.Timestamp.Append(int64(meta.Timestamp))

	switch meta.Origin {
	case support.TraceOriginSampling:
		r.sampleWriter.Value.Append(1)
		r.sampleWriter.SampleType.AppendString("samples")
		r.sampleWriter.SampleUnit.AppendString("count")
		r.sampleWriter.PeriodType.AppendString("cpu")
		r.sampleWriter.PeriodUnit.AppendString("nanoseconds")
	case support.TraceOriginOffCPU:
		r.sampleWriter.Value.Append(meta.OffTime)
		r.sampleWriter.SampleType.AppendString("wallclock")
		r.sampleWriter.SampleUnit.AppendString("nanoseconds")
		r.sampleWriter.PeriodType.AppendString("samples")
		r.sampleWriter.PeriodUnit.AppendString("count")
	}

	return nil
}

func (r *ParcaReporter) addMetadataForPID(pid libpf.PID, lb *labels.Builder) bool {
	cache := true

	for _, p := range r.metadataProviders {
		cacheable := p.AddMetadata(pid, lb)
		cache = cache && cacheable
	}

	return cache
}

func (r *ParcaReporter) labelsForTID(tid, pid libpf.PID, comm string, cpu int) labelRetrievalResult {
	if labels, exists := r.labels.Get(tid); exists {
		return labels
	}

	lb := &labels.Builder{}
	lb.Set("node", r.nodeName)
	lb.Set("__meta_thread_comm", comm)
	lb.Set("__meta_thread_id", fmt.Sprint(tid))
	lb.Set("__meta_cpu", fmt.Sprint(cpu))
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
func (r *ParcaReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *samples.TraceEventMeta) {
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *ParcaReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.executables.Get(fileID)
	return known
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
	if !r.disableSymbolUpload {
		r.uploader.Upload(context.TODO(), args.FileID, args.GnuBuildID, args.Open)
	}

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

type OfflineModeConfig struct {
	StoragePath      string
	RotationInterval time.Duration
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
	offlineModeConfig *OfflineModeConfig,
) (*ParcaReporter, error) {
	if offlineModeConfig != nil && !disableSymbolUpload {
		return nil, errors.New("Illogical configuration: offline mode with symbol upload enabled")
	}
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

	var loggedStacks *lru.SyncedLRU[libpf.TraceHash, struct{}]
	if offlineModeConfig != nil {
		loggedStacks, err = lru.NewSynced[libpf.TraceHash, struct{}](cacheSize, libpf.TraceHash.Hash32)
		if err != nil {
			return nil, err
		}
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
		offlineModeConfig:           offlineModeConfig,
		offlineModeLoggedStacks:     loggedStacks,
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

const DATA_FILE_EXTENSION string = ".padata"
const DATA_FILE_COMPRESSED_EXTENSION string = ".padata.zst"

// initialScan inspects the storage directory to determine its size, and whether there are any
// uncompressed files lying around.
// It returns a map of filenames to sizes, a list of uncompressed files, and the total size.
func initialScan(storagePath string) (map[string]uint64, []string, uint64, error) {
	existingFileSizes := make(map[string]uint64)
	uncompressedFiles := make([]string, 0)
	totalSize := uint64(0)

	files, err := os.ReadDir(storagePath)
	if err != nil {
		return nil, nil, 0, err
	}

	for _, file := range files {
		fname := file.Name()
		if !file.Type().IsRegular() {
			log.Warnf("Directory or special file %s in storage path; skipping", fname)
			continue
		}
		if strings.HasSuffix(fname, DATA_FILE_COMPRESSED_EXTENSION) {
			info, err := file.Info()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed stat of file %s: %w", fname, err)
			}
			sz := uint64(info.Size())
			existingFileSizes[fname] = sz
			totalSize += sz
		} else if strings.HasSuffix(fname, DATA_FILE_EXTENSION) {
			uncompressedFiles = append(uncompressedFiles, fname)
		} else {
			log.Warnf("Unrecognized file %s; skipping", fname)
		}
	}
	return existingFileSizes, uncompressedFiles, totalSize, nil
}

func compressFile(file io.Reader, fpath, compressedFpath string) error {
	compressedLog, err := os.OpenFile(compressedFpath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0660)
	if err != nil {
		return fmt.Errorf("Failed to create compressed file %s for log rotation: %w", compressedFpath, err)
	}
	zstdWriter, err := zstd.NewWriter(compressedLog)
	if err != nil {
		return fmt.Errorf("Failed to create zstd writer for file %s: %w", compressedFpath, err)
	}
	if _, err = io.Copy(zstdWriter, file); err != nil {
		return fmt.Errorf("Failed to write compressed log %s: %w", compressedFpath, err)
	}
	zstdWriter.Close()
	if err = compressedLog.Close(); err != nil {
		return fmt.Errorf("Failed to close compressed file %s: %w", compressedFpath, err)
	}
	log.Debugf("Successfully wrote compressed file %s", compressedFpath)

	err = os.Remove(fpath)
	if err != nil {
		return fmt.Errorf("Failed to remove uncompressed file: %w", err)
	}
	return nil
}

func setupOfflineModeLog(fpath string) (*os.File, error) {
	// Open the log file
	file, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0660)
	if err != nil {
		return nil, fmt.Errorf("failed to create new offline mode file %s: %w", fpath, err)
	}

	// magic number (4 bytes, 0xA6E7CCCA), followed by format version (2 bytes),
	// followed by number of batches (2 bytes)
	if _, err = file.Write([]byte{0xA6, 0xE7, 0xCC, 0xCA, 0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("failed to write to offline mode file %s: %w", fpath, err)
	}

	return file, nil
}

func (r *ParcaReporter) rotateOfflineModeLog() error {
	fpath := fmt.Sprintf("%s/%d-%d%s", r.offlineModeConfig.StoragePath, time.Now().Unix(), os.Getpid(), DATA_FILE_EXTENSION)

	logFile, err := setupOfflineModeLog(fpath)
	if err != nil {
		return fmt.Errorf("Failed to create new log %s for offline mode: %w", fpath, err)

	}
	// We are connected to the new log, let's take the old one and compress it
	r.offlineModeLogMu.Lock()
	oldLog := r.offlineModeLogFile
	r.offlineModeLogFile = logFile
	oldFpath := r.offlineModeLogPath
	r.offlineModeLogPath = fpath
	r.offlineModeLoggedStacks.Purge()
	r.offlineModeNBatchesInCurrentFile = 0
	r.offlineModeLogMu.Unlock()
	defer oldLog.Close()
	_, err = oldLog.Seek(0, 0)
	if err != nil {
		return errors.New("Failed to seek to beginning of file")
	}
	compressedFpath := fmt.Sprintf("%s.zst", oldFpath)
	return compressFile(oldLog, oldFpath, compressedFpath)
}

func (r *ParcaReporter) runOfflineModeRotation(ctx context.Context) error {
	_, uncompressedFiles, _, err := initialScan(r.offlineModeConfig.StoragePath)
	if err != nil {
		return err
	}

	for _, fname := range uncompressedFiles {
		fpath := path.Join(r.offlineModeConfig.StoragePath, fname)
		compressedFpath := fmt.Sprintf("%s.zst", fpath)
		f, err := os.Open(fpath)
		if err != nil {
			return err
		}

		err = compressFile(f, fpath, compressedFpath)
		if err != nil {
			return err
		}
	}
	tick := time.NewTicker(r.offlineModeConfig.RotationInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.stopSignal:
			return nil
		case <-tick.C:
			r.rotateOfflineModeLog()
		}
	}
}

func (r *ParcaReporter) Start(mainCtx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	if !r.disableSymbolUpload {
		go func() {
			if err := r.uploader.Run(ctx); err != nil {
				log.Fatalf("Running symbol uploader failed: %v", err)
			}
		}()
	}

	if r.offlineModeConfig != nil {
		if err := os.MkdirAll(r.offlineModeConfig.StoragePath, 0770); err != nil {
			return fmt.Errorf("error creating offline mode storage: %v", err)
		}
		go func() {
			if err := r.runOfflineModeRotation(ctx); err != nil {
				log.Fatalf("Running offline mode rotation failed: %v", err)
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
				if r.offlineModeConfig != nil {
					if err := r.logDataForOfflineMode(ctx, buf); err != nil {
						log.Errorf("error producing offline mode file: %v.\nForcing rotation as the file might be corrupt.", err)
						if err := r.rotateOfflineModeLog(); err != nil {
							log.Errorf("failed to rotate log: %v", err)
						}
					}
				} else {
					if err := r.reportDataToBackend(ctx, buf); err != nil {
						log.Errorf("Request failed: %v", err)
					}
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

	return nil
}

func (r *ParcaReporter) logDataForOfflineMode(ctx context.Context, buf *bytes.Buffer) error {
	record, nLabelCols := r.buildSampleRecord(ctx)
	defer record.Release()

	if record.NumRows() == 0 {
		log.Debugf("Skip logging batch with no samples")
		return nil
	}

	buf.Reset()

	w := ipc.NewWriter(buf,
		ipc.WithSchema(record.Schema()),
		ipc.WithAllocator(r.mem),
	)

	if err := w.Write(record); err != nil {
		return fmt.Errorf("failed to write samples: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close samples writer: %w", err)
	}

	r.offlineModeLogMu.Lock()
	defer r.offlineModeLogMu.Unlock()
	if r.offlineModeLogFile == nil {
		fpath := fmt.Sprintf("%s/%d-%d%s", r.offlineModeConfig.StoragePath, time.Now().Unix(), os.Getpid(), DATA_FILE_EXTENSION)

		logFile, err := setupOfflineModeLog(fpath)
		if err != nil {
			return fmt.Errorf("failed to set up offline mode log file: %w", err)
		}
		r.offlineModeLogFile = logFile
		r.offlineModeLogPath = fpath
		r.offlineModeLoggedStacks.Purge()
		r.offlineModeNBatchesInCurrentFile = 0
	}

	sz := uint32(buf.Len())
	if err := binary.Write(r.offlineModeLogFile, binary.BigEndian, sz); err != nil {
		return fmt.Errorf("failed to write to log %s: %w", r.offlineModeLogPath, err)
	}

	if _, err := r.offlineModeLogFile.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("Failed to write to log %s: %v", r.offlineModeLogPath, err)
	}

	r.sampleWriteRequestBytes.Add(float64(buf.Len()))

	sidFieldIdx := nLabelCols
	sidField := record.Schema().Field(sidFieldIdx)
	if sidField.Name != "stacktrace_id" {
		panic("mismatched schema: last field is named " + sidField.Name)
	}

	// we don't use the two-value variant because if
	// panics happen here, it can only represent a programming bug
	// (schema of the record we just created doesn't match our expectations)
	ree := record.Column(sidFieldIdx).(*array.RunEndEncoded)
	dict := ree.Values().(*array.Dictionary)
	b := array.NewBuilder(r.mem, dict.DataType()).(*array.BinaryDictionaryBuilder)
	defer b.Release()

	binDict := dict.Dictionary().(*array.Binary)
	runEnds := ree.RunEndsArr().(*array.Int32)
	for i := 0; i < runEnds.Len(); i++ {
		if !dict.IsNull(i) {
			v := binDict.Value(dict.GetValueIndex(i))
			hash, err := libpf.TraceHashFromBytes(v)
			if err != nil {
				return fmt.Errorf("Failed to construct hash from bytes: %w", err)
			}
			_, exists := r.offlineModeLoggedStacks.Get(hash)
			r.offlineModeLoggedStacks.Add(hash, struct{}{})
			if exists {
				continue
			}
			if err := b.Append(v); err != nil {
				// how can appending to an in-memory buffer ever fail?
				// From a brief glance at the Arrow source code, it doesn't seem like it can.
				return fmt.Errorf("failed to construct IDs record; this should never happen. err: %w", err)
			}
		}
	}
	idsDict := b.NewArray().(*array.Dictionary)
	defer idsDict.Release()
	idsBinary := idsDict.Dictionary().(*array.Binary)

	rec, err := r.buildStacktraceRecord(ctx, idsBinary)
	if err != nil {
		return fmt.Errorf("Failed to build stacktrace record: %v", err)
	}

	buf.Reset()
	w = ipc.NewWriter(buf,
		ipc.WithSchema(rec.Schema()),
		ipc.WithAllocator(r.mem),
	)

	if err := w.Write(rec); err != nil {
		return fmt.Errorf("Failed to write stacktrace record: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("Failed to close stacktrace writer: %v", err)
	}

	sz = uint32(buf.Len())
	if err := binary.Write(r.offlineModeLogFile, binary.BigEndian, sz); err != nil {
		return fmt.Errorf("Failed to write to log %s: %v", r.offlineModeLogPath, err)
	}
	if _, err := r.offlineModeLogFile.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("Failed to write to log %s: %v", r.offlineModeLogPath, err)
	}
	r.stacktraceWriteRequestBytes.Add(float64(buf.Len()))
	// We need to fsync before updating the number of records at the head of the file. Otherwise,
	// the kernel might persist that update before persisting the record we just wrote, and we might
	// read a corrupt file.
	if err := r.offlineModeLogFile.Sync(); err != nil {
		return fmt.Errorf("Failed to fsync log %s: %v", r.offlineModeLogPath, err)
	}

	r.offlineModeNBatchesInCurrentFile += 1
	n := r.offlineModeNBatchesInCurrentFile
	log.Debugf("wrote batch %d", n)

	if _, err = r.offlineModeLogFile.WriteAt([]byte{byte(n / 256), byte(n)}, 6); err != nil {
		return fmt.Errorf("Failed to write to log %s: %v", r.offlineModeLogPath, err)
	}

	return nil
}

// reportDataToBackend creates and sends out an arrow record for a Parca backend.
func (r *ParcaReporter) reportDataToBackend(ctx context.Context, buf *bytes.Buffer) error {
	record, _ := r.buildSampleRecord(ctx)
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
	if err == io.EOF || len(resp.Record) == 0 {
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
// samples up to this moment, as well as the number of label columns.
// The arrow record does not contain the full stacktraces, only
// the stacktrace IDs, depending on whether the backend already knows the
// stacktrace ID, it might request the full stacktrace from the agent. The
// second return value contains all the raw samples, which can be used to
// resolve the stacktraces.
func (r *ParcaReporter) buildSampleRecord(ctx context.Context) (arrow.Record, int) {
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
	w.Temporality.ree.Append(rows)
	w.Temporality.bd.AppendString("delta")
	w.Period.ree.Append(rows)
	// Since the period is of type cpu nanoseconds it is the time between
	// samples.
	w.Period.ib.Append(1e9 / int64(r.samplesPerSecond))
	w.Duration.ree.Append(rows)
	w.Duration.ib.Append(time.Second.Nanoseconds())

	return w.NewRecord(), len(w.labelBuilders)
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
