/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	profilestoregrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	profilestorepb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/profilestore/v1alpha1"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	lru "github.com/elastic/go-freelru"
	"github.com/klauspost/compress/zstd"
	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// Assert that we implement the full ParcaReporter interface (which itself
// embeds otel's reporter.Reporter, so the otel contract is covered too).
var _ ParcaReporter = (*arrowReporter)(nil)

// GPU sample reporting. PC samples are reported as a raw sample count
// (gpu_pcsample/count); the per-sample weight -- NsPerSample = 2^SamplingFactor
// / clock_hz, derived from the per-pid GpuConfig emitted by parcagpu's
// gpu_config USDT probe -- is carried in the period, mirroring CPU sampling
// (samples/count : cpu/nanoseconds). value × period totals nanoseconds of GPU
// time, but the value itself is the honest sample count and stays correct even
// before the GpuConfig arrives (only the period is unknown until then).
//
// PC sampling observes all PC activity -- normally scheduled instructions as
// well as stalls -- so the sample_type is gpu_pcsample, not a "stall time".
//
// When mergeGpuProfiles is true (legacy), kernel timings and PC samples are
// folded into a single gpu_time/nanoseconds sample_type differentiated by a
// gpu_view label; there the PC count is converted to nanoseconds inline so both
// views stay summable in one time unit. When false (default), they go into
// separate sample_types: gpu_kernel_time/nanoseconds for exact kernel
// durations, gpu_pcsample/count for PC sample counts.
//
// The sample_type/unit and gpu_view label strings are written as literals at
// the call sites (matching the cpu/off-cpu cases above) so the full
// profile-type tuple and view label are visible where they're emitted.

// gpuNsPerSample looks up the per-pid GpuConfig (populated from parcagpu's
// gpu_config USDT probe) and returns the nanoseconds of GPU time attributable
// to one PC sample observation, or 0 if the config has not yet arrived. The
// non-merged path uses it as the sample's period (the raw PC count from
// TraceEventMeta.OffTime stays the value); the merged path multiplies the raw
// count by it to convert to nanoseconds.
func (r *arrowReporter) gpuNsPerSample(pid libpf.PID) int64 {
	cfg, ok := gpu.LoadGpuConfig(uint32(pid))
	if !ok {
		gpu.WarnMissingGpuConfig(uint32(pid))
		return 0
	}
	return cfg.NsPerSample()
}

// processInfo stores metadata about the process.
type processInfo struct {
	comm           string
	mainExecutable libpf.FileID
}

// labelRetrievalResult is a result of a label retrieval.
//
// The two label sets are kept apart because the export backends need them
// differently. Arrow flattens both into one row of label columns; OTLP puts
// `resource` on the ResourceProfiles (it is constant for the process) and
// `sample` on the individual Sample. Merging them here would force the OTLP
// path to guess which is which from label names alone, and relabel configs
// can produce arbitrary names.
type labelRetrievalResult struct {
	// resource holds the process-invariant labels: node, the metadata
	// providers' output, relabel results, and job=oomprof.
	resource labels.Labels
	// sample holds the per-sample patches: cpu, thread_id, thread_name.
	sample labels.Labels
	keep   bool
}

// forEach calls fn for every label in both sets. Callers that flatten the two
// (the arrow writers) use this so a change to the split cannot silently drop a
// label column.
func (r labelRetrievalResult) forEach(fn func(l labels.Label)) {
	r.resource.Range(fn)
	r.sample.Range(fn)
}

// get returns the value of a label from either set, sample first. It exists for
// callers that only care about the flattened view, which is how the arrow
// backends and the label tests see the world.
func (r labelRetrievalResult) get(name string) string {
	if v := r.sample.Get(name); v != "" {
		return v
	}
	return r.resource.Get(name)
}

// arrowReporter is the concrete arrow-row builder behind the
// ParcaReporter interface. It transforms otel trace events and
// parca-agent-specific memory traces into OTLP/profiles-compliant arrow
// records and ships them to the configured backend.
type arrowReporter struct {
	// client for the connection to the receiver.
	client profilestoregrpc.ProfileStoreServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// To fill in the profiles signal with the relevant information,
	// this structure holds in long-term storage information that might
	// be duplicated in other places but not accessible for arrowReporter.

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]

	// lbls resolves the per-process and per-sample label sets. Shared with
	// the OTLP backend so relabel semantics cannot drift between them.
	lbls *processLabeler

	// execs owns the executable cache, debuginfo upload, and the probes
	// hook; metrics bridges the unwinder's metrics into prometheus;
	// counters holds the backend-independent sample counters. All three are
	// shared with the OTLP backend.
	execs    *execTracker
	metrics  *metricsBridge
	counters *reporterCounters

	// samples stores the so far received samples (v1 schema).
	sampleWriter   *SampleWriter
	sampleWriterMu sync.Mutex

	// v2 schema support
	useV2Schema      bool
	sampleWriterV2   *SampleWriterV2
	sampleWriterV2Mu sync.Mutex

	// mergeGpuProfiles reports GPU kernel timing and GPU PC sampling under a
	// single gpu_time/nanoseconds sample_type, with a gpu_view label
	// distinguishing the two views.
	mergeGpuProfiles bool

	// stacks stores known stacks.
	stacks *lru.SyncedLRU[libpf.TraceHash, libpf.Frames]

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

	// node name
	nodeName string

	// Our own metrics
	sampleWrites                prometheus.Counter
	sampleWriteRequestBytes     prometheus.Counter
	stacktraceWriteRequestBytes prometheus.Counter
	writeRequestsTotal          *prometheus.CounterVec

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

	oomState     *oomprof.State
	reportAllocs bool // whether to report allocs in memory profiles

	// logProvider is set when the reporter was constructed with a non-nil
	// gRPC conn; otherwise Logger() hands out the OTel no-op logger and
	// emit calls are silently dropped. Owned by the reporter so Shutdown can
	// flush + close it when the reporter is torn down.
	logProvider *sdklog.LoggerProvider

	// tracerProvider is the trace-side twin of logProvider: set iff
	// constructed with a non-nil gRPC conn, otherwise Tracer() returns a
	// no-op. Owned here so Shutdown can flush in-flight spans before exit.
	tracerProvider *sdktrace.TracerProvider

}

// ProbesHook is the small surface that the probes BPF service exposes back
// to the reporter so it can be notified of newly-observed executables.
// Defined as an interface to avoid an import cycle with the probes package.
type ProbesHook interface {
	OnExecutable(filePath string, fileID libpf.FileID)
}

// SetProbes wires the probes BPF service onto this reporter. Must be called
// before Start so the hook is in place before ReportExecutable can fire.
func (r *arrowReporter) SetProbes(p ProbesHook) {
	r.execs.probes = p
}

// Assert that *arrowReporter satisfies the ParcaReporter interface.
var _ ParcaReporter = (*arrowReporter)(nil)

// Logger returns an OTel logs Logger bound to the given scope name.
// In offline mode (no gRPC conn was supplied at construction) the SDK
// LoggerProvider is nil; we return the OTel no-op Logger so callers can
// treat Logger as unconditional and Emit calls become inert.
func (r *arrowReporter) Logger(scope string) otellog.Logger {
	return logger(r.logProvider, scope)
}

func (r *arrowReporter) Tracer(scope string) oteltrace.Tracer {
	return tracer(r.tracerProvider, scope)
}

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

func (r *arrowReporter) SupportsReportTraceEvent() bool { return true }

// maybeFixTruncation fixes string truncation done at the byte level
// (at maxLen) to be done at the rune level instead.
//
// It returns the correctly truncated utf-8 string if possible;
// otherwise "", false.
func maybeFixTruncation(s string, maxLen int) (string, bool) {
	if utf8.ValidString(s) {
		return s, true
	}
	// maybe we truncated in the middle of a rune -- if that's the case,
	// truncate the entire rune.
	plausibleTruncatedRuneBegin := -1
	if len(s) == maxLen {
		i := 0
		for ; i < 2; i += 1 {
			idx := maxLen - i - 1
			if s[idx]&0xC0 != 0x80 {
				plausibleTruncatedRuneBegin = idx
				break
			}
		}
	}
	if plausibleTruncatedRuneBegin != -1 {
		s = s[0:plausibleTruncatedRuneBegin]
		if !utf8.ValidString(s) {
			return "", false
		}
	} else {
		return "", false
	}
	return s, true
}

// ReportTraceEvent enqueues reported trace events for the OTLP reporter.
//
// Memory-origin traces do not flow through this method — they take the
// dedicated ReportMemoryTraces path so a memory batch can hold the writer
// lock once for many rows.
func (r *arrowReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta,
) error {
	traceHash := traceutil.HashTrace(trace)
	// This is an LRU so we need to check every time if the stack is already
	// known, as it might have been evicted.
	if _, exists := r.stacks.Get(traceHash); !exists {
		// Store the Frames directly, no allocation needed
		r.stacks.Add(traceHash, trace.Frames)
	}

	labelRetrievalResult := r.lbls.labelsForTID(meta.TID, meta.PID, meta.Comm, meta.CPU, meta.Origin, meta.EnvVars)

	if !labelRetrievalResult.keep {
		r.counters.skippedByRelabeling.Inc()
		log.Debugf("Skipping trace event for PID %d, as it was filtered out by relabeling", meta.PID)
		return nil
	}

	if len(trace.Frames) == 0 {
		r.counters.emptySamples.Inc()
	}

	// Dispatch to v2 path if enabled
	if r.useV2Schema {
		return r.reportTraceEventV2(trace, traceHash, meta, labelRetrievalResult)
	}

	r.sampleWriterMu.Lock()
	defer r.sampleWriterMu.Unlock()

	buf := [16]byte{}
	traceHash.PutBytes16(&buf)

	writeSample := func(value int64, duration int64, per int64, producer, sampleType, sampleUnit, periodType, periodUnit string) {
		// Write labels. Both sets are flattened into label columns; the
		// resource/sample split only matters for the OTLP backend.
		labelRetrievalResult.forEach(func(lbl labels.Label) {
			r.sampleWriter.Label(lbl.Name).AppendString(lbl.Value)
		})

		// Write custom labels
		for k, v := range trace.CustomLabels {
			if !utf8.ValidString(k.String()) {
				log.Warnf("ignoring non-UTF8 label: %s", hex.EncodeToString([]byte(k.String())))
				continue
			}
			v, ok := maybeFixTruncation(v.String(), support.CustomLabelMaxValLen-1)
			if !ok {
				log.Warnf("ignoring non-UTF8 value for label %s: %s", k, hex.EncodeToString([]byte(v)))
				continue
			}
			r.sampleWriter.Label(k.String()).AppendString(v)
		}

		// Write sample data
		r.sampleWriter.StacktraceID.Append(buf[:])
		r.sampleWriter.Timestamp.Append(int64(meta.Timestamp))
		r.sampleWriter.Value.Append(value)
		r.sampleWriter.SampleType.AppendString(sampleType)
		r.sampleWriter.SampleUnit.AppendString(sampleUnit)
		r.sampleWriter.PeriodType.AppendString(periodType)
		r.sampleWriter.PeriodUnit.AppendString(periodUnit)
		r.sampleWriter.Producer.AppendString(producer)
		r.sampleWriter.Duration.Append(duration)
		r.sampleWriter.Period.Append(per)
	}

	switch meta.Origin {
	case support.TraceOriginSampling:
		writeSample(1, int64(time.Second.Nanoseconds()), 1e9/int64(r.samplesPerSecond), "parca_agent", "samples", "count", "cpu", "nanoseconds")
		r.sampleWriter.Temporality.AppendString("delta")
		r.counters.cpuSamples.Inc()
	case support.TraceOriginOffCPU:
		writeSample(meta.Value, int64(time.Second.Nanoseconds()), 1e9/int64(r.samplesPerSecond), "parca_agent", "wallclock", "nanoseconds", "samples", "count")
		r.sampleWriter.Temporality.AppendString("delta")
		r.counters.offcpuSamples.Inc()
	case support.TraceOriginCuda:
		if r.mergeGpuProfiles {
			r.sampleWriter.Label("gpu_view").AppendString("kernel_time")
			writeSample(meta.Value, time.Second.Nanoseconds(), 1,
				"parca_agent", "gpu_time", "nanoseconds", "gpu_time", "nanoseconds")
		} else {
			writeSample(meta.Value, time.Second.Nanoseconds(), 1,
				"parca_agent", "gpu_kernel_time", "nanoseconds", "gpu_kernel_time", "nanoseconds")
		}
		r.sampleWriter.Temporality.AppendString("delta")
		r.counters.gpuSamples.Inc()
	case support.TraceOriginGpuPC:
		nsPerSample := r.gpuNsPerSample(meta.PID)
		if r.mergeGpuProfiles {
			value := meta.Value
			if nsPerSample > 0 {
				value *= nsPerSample
			}
			r.sampleWriter.Label("gpu_view").AppendString("pc_sample")
			writeSample(value, time.Second.Nanoseconds(), 1,
				"parca_agent", "gpu_time", "nanoseconds", "gpu_time", "nanoseconds")
		} else {
			writeSample(meta.Value, time.Second.Nanoseconds(), nsPerSample,
				"parca_agent", "gpu_pcsample", "count", "gpu_pcsample", "nanoseconds")
		}
		r.sampleWriter.Temporality.AppendString("delta")
		r.counters.gpuPCSamples.Inc()
	default:
		log.Warnf("unknown trace origin: %d", meta.Origin)
	}

	return nil
}

// reportTraceEventV2 handles trace events using the v2 schema with inline
// stacktraces. Memory-origin traces do not pass through this method —
// they are written by ReportMemoryTraces.
func (r *arrowReporter) reportTraceEventV2(trace *libpf.Trace, traceHash libpf.TraceHash,
	meta *samples.TraceEventMeta, labelResult labelRetrievalResult,
) error {

	r.sampleWriterV2Mu.Lock()
	defer r.sampleWriterV2Mu.Unlock()

	switch meta.Origin {
	case support.TraceOriginSampling:
		r.writeSampleV2(trace, traceHash, meta, labelResult, 1, uint64(time.Second.Nanoseconds()), 1e9/int64(r.samplesPerSecond), true, "parca_agent", "samples", "count", "cpu", "nanoseconds")
		r.counters.cpuSamples.Inc()
	case support.TraceOriginOffCPU:
		r.writeSampleV2(trace, traceHash, meta, labelResult, meta.Value, uint64(time.Second.Nanoseconds()), 0, true, "parca_agent", "wallclock", "nanoseconds", "samples", "count")
		r.counters.offcpuSamples.Inc()
	case support.TraceOriginCuda:
		if r.mergeGpuProfiles {
			r.sampleWriterV2.Label("gpu_view").AppendString("kernel_time")
			r.writeSampleV2(trace, traceHash, meta, labelResult, meta.Value,
				uint64(time.Second.Nanoseconds()), 1, true,
				"parca_agent", "gpu_time", "nanoseconds", "gpu_time", "nanoseconds")
		} else {
			r.writeSampleV2(trace, traceHash, meta, labelResult, meta.Value,
				uint64(time.Second.Nanoseconds()), 1, true,
				"parca_agent", "gpu_kernel_time", "nanoseconds", "gpu_kernel_time", "nanoseconds")
		}
		r.counters.gpuSamples.Inc()
	case support.TraceOriginGpuPC:
		nsPerSample := r.gpuNsPerSample(meta.PID)
		if r.mergeGpuProfiles {
			value := meta.Value
			if nsPerSample > 0 {
				value *= nsPerSample
			}
			r.sampleWriterV2.Label("gpu_view").AppendString("pc_sample")
			r.writeSampleV2(trace, traceHash, meta, labelResult, value,
				uint64(time.Second.Nanoseconds()), 1, true,
				"parca_agent", "gpu_time", "nanoseconds", "gpu_time", "nanoseconds")
		} else {
			r.writeSampleV2(trace, traceHash, meta, labelResult, meta.Value,
				uint64(time.Second.Nanoseconds()), nsPerSample, true,
				"parca_agent", "gpu_pcsample", "count", "gpu_pcsample", "nanoseconds")
		}
		r.counters.gpuPCSamples.Inc()
	default:
		log.Warnf("unknown trace origin: %d", meta.Origin)
	}

	return nil
}

func (r *arrowReporter) writeSampleV2(
	trace *libpf.Trace,
	traceHash libpf.TraceHash,
	meta *samples.TraceEventMeta,
	labelResult labelRetrievalResult,
	value int64, duration uint64, per int64,
	delta bool,
	producer, sampleType, sampleUnit, periodType, periodUnit string,
) {
	labelResult.forEach(func(lbl labels.Label) {
		r.sampleWriterV2.Label(lbl.Name).AppendString(lbl.Value)
	})

	for k, v := range trace.CustomLabels {
		ks := k.String()
		if !utf8.ValidString(ks) {
			log.Warnf("ignoring non-UTF8 label: %s", hex.EncodeToString([]byte(ks)))
			continue
		}
		vs, ok := maybeFixTruncation(v.String(), support.CustomLabelMaxValLen-1)
		if !ok {
			log.Warnf("ignoring non-UTF8 value for label %s: %s", ks, hex.EncodeToString([]byte(vs)))
			continue
		}
		r.sampleWriterV2.Label(ks).AppendString(vs)
	}

	r.sampleWriterV2.Stacktrace.AppendStacktrace(traceHash, trace.Frames, r.appendLocationV2)
	r.sampleWriterV2.StacktraceID.AppendBytes([16]byte(traceHash.Bytes()))

	r.sampleWriterV2.Timestamp.Append(arrow.Timestamp(int64(meta.Timestamp)))
	r.sampleWriterV2.Value.Append(value)
	r.sampleWriterV2.SampleType.AppendString(sampleType)
	r.sampleWriterV2.SampleUnit.AppendString(sampleUnit)
	r.sampleWriterV2.PeriodType.AppendString(periodType)
	r.sampleWriterV2.PeriodUnit.AppendString(periodUnit)
	r.sampleWriterV2.Producer.AppendString(producer)
	r.sampleWriterV2.Duration.Append(duration)
	r.sampleWriterV2.Period.Append(per)

	if delta {
		r.sampleWriterV2.Temporality.AppendString("delta")
	} else {
		r.sampleWriterV2.Temporality.AppendNull()
	}
}

// appendLocationV2 resolves a frame and appends it to the location dictionary.
// It uses the libpf.Frame value as the deduplication key, skipping resolution
// and arrow writes when the frame has already been seen.
// Functions are dictionary-encoded via FunctionDictBuilderV2.
func (r *arrowReporter) appendLocationV2(frame libpf.Frame) uint32 {
	b := r.sampleWriterV2.Stacktrace

	if idx, ok := b.LocationIndex[frame]; ok {
		return idx
	}

	idx := uint32(len(b.LocationIndex))
	b.LocationIndex[frame] = idx

	// Record line list offset for this location (before writing any lines)
	b.lineListOffsets.Append(int32(b.lineNumber.Len()))
	b.locAddress.Append(uint64(frame.AddressOrLineno))

	if frame.Type.IsAbort() {
		b.locFrameType.AppendString(frame.Type.String())
		b.locMappingFile.AppendString("agent-internal-error-frame")
		b.locMappingID.AppendNull()

		b.lineNumber.Append(0)
		b.lineColumn.Append(0)
		b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
			SystemName: "aborted",
			Filename:   "",
			StartLine:  0,
		}))

		return idx
	}

	switch frameKind := frame.Type; frameKind {
	case libpf.NativeFrame:
		b.locFrameType.AppendString(frame.Type.String())

		var execInfo metadata.ExecInfo
		var fid libpf.FileID
		var exists bool

		if frame.Mapping.Valid() {
			m := frame.Mapping.Value()
			if m.File != (libpf.FrameMappingFile{}) {
				mf := m.File.Value()
				fid = mf.FileID
				execInfo, exists = r.executables.Get(mf.FileID)
			}
		}

		if exists {
			b.locMappingFile.AppendString(execInfo.FileName)
			if execInfo.BuildID != "" {
				b.locMappingID.AppendString(execInfo.BuildID)
			} else {
				b.locMappingID.AppendString(fid.StringNoQuotes())
			}
		} else {
			b.locMappingFile.AppendString("UNKNOWN")
			b.locMappingID.AppendNull()
		}
		// No lines for native frames

	case libpf.KernelFrame:
		b.locFrameType.AppendString(frame.Type.String())
		b.locMappingFile.AppendString("[kernel.kallsyms]")
		b.locMappingID.AppendNull()

		var execInfo metadata.ExecInfo
		var exists bool
		if frame.Mapping.Valid() {
			m := frame.Mapping.Value()
			if m.File != (libpf.FrameMappingFile{}) {
				mf := m.File.Value()
				execInfo, exists = r.executables.Get(mf.FileID)
			}
		}
		var moduleName string
		if exists {
			moduleName = execInfo.FileName
		} else {
			moduleName = "vmlinux"
		}

		var symbol string
		var lineNumber uint64
		if frame.FunctionName.String() != "" {
			symbol = frame.FunctionName.String()
			lineNumber = uint64(frame.SourceLine)
		} else {
			symbol = "UNKNOWN"
		}

		b.lineNumber.Append(lineNumber)
		b.lineColumn.Append(0)
		b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
			SystemName: symbol,
			Filename:   moduleName,
			StartLine:  0,
		}))

	case libpf.CUDAPCFrame:
		// CUDA PC sample: a function-relative kernel offset. One mapping per
		// cubin (build ID = cubin CRC FileID, never a per-function ID). The
		// kernel's mangled name rides as the system name of a placeholder line
		// (line 0); the backend resolves the real source line per function,
		// gated downstream on the "cuda-pc" frame type.
		b.locFrameType.AppendString(frame.Type.String())

		var fid libpf.FileID
		if frame.Mapping.Valid() {
			mf := frame.Mapping.Value().File.Value()
			fid = mf.FileID
			b.locMappingFile.AppendString(mf.FileName.String())
		} else {
			b.locMappingFile.AppendNull()
		}
		b.locMappingID.AppendString(fid.StringNoQuotes())

		b.lineNumber.Append(0)
		b.lineColumn.Append(0)
		b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
			SystemName: frame.FunctionName.String(),
			Filename:   "",
			StartLine:  0,
		}))

	default:
		// Interpreted frames (Python, Ruby, V8 etc.)
		// Forward the Mapping's GnuBuildID when present so the
		// backend can do sourcemap resolution.
		b.locFrameType.AppendString(frame.Type.String())
		b.locMappingFile.AppendNull()
		if frame.Mapping.Valid() && frame.Mapping.Value().File.Value().GnuBuildID != "" {
			b.locMappingID.AppendString(frame.Mapping.Value().File.Value().GnuBuildID)
		} else {
			b.locMappingID.AppendNull()
		}

		var lineNumber uint64
		var functionName, filePath string

		if frame.FunctionName.String() != "" {
			functionName = frame.FunctionName.String()
			filePath = frame.SourceFile.String()
			lineNumber = uint64(frame.SourceLine)
		} else {
			functionName = "UNREPORTED"
			filePath = "UNREPORTED"
		}

		// Empty path causes the backend to crash
		if filePath == "" {
			filePath = "UNKNOWN"
		}

		b.lineNumber.Append(lineNumber)
		b.lineColumn.Append(uint64(frame.SourceColumn))
		b.funcIndices.Append(b.funcDict.AppendFunction(FunctionV2{
			SystemName: functionName,
			Filename:   filePath,
			StartLine:  0,
		}))
	}

	return idx
}

// ReportFramesForTrace is a NOP for arrowReporter.
func (r *arrowReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for arrowReporter.
func (r *arrowReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *samples.TraceEventMeta) {
}

// ExecutableKnown returns true if the metadata of the Executable specified by
// fileID is cached in the reporter.
func (r *arrowReporter) ExecutableKnown(fileID libpf.FileID) bool {
	return r.execs.ExecutableKnown(fileID)
}

func (r *arrowReporter) ReportExecutable(args *reporter.ExecutableMetadata) {
	r.execs.ReportExecutable(args)
}

// ReportHostMetadata enqueues host metadata.
func (r *arrowReporter) ReportHostMetadata(metadataMap map[string]string) {
	// noop
}

// ReportHostMetadataBlocking enqueues host metadata.
func (r *arrowReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration,
) error {
	// noop
	return nil
}

// memorySamplePeriod is the assumed inter-allocation period used as the
// pprof "period" for memory rows. 512 KiB matches the previous behavior;
// long term this should be derived from the target process.
const memorySamplePeriod int64 = 512 * 1024

// ReportMemoryTraces emits inuse / alloc rows for a batch of memory-
// attributed traces. All samples share `meta` (one process snapshot), so
// labels are computed once and the v2 writer lock is taken once for the
// whole call.
//
// The agent v2 schema is the only target. The trace's call stack is encoded as
// a libpf.Trace of native frames with the build ID stashed on
// FunctionName so the location builder can synthesize a mapping for the
// possibly-gone process.
func (r *arrowReporter) ReportMemoryTraces(
	memSamples []oomprof.Sample, meta oomprof.SampleMeta,
) error {
	if !r.useV2Schema {
		// v1 never carried memory profiles end-to-end; drop loudly so
		// misconfigurations are obvious.
		return fmt.Errorf("ReportMemoryTraces requires the v2 schema; v1 memory reporting is unsupported")
	}
	if len(memSamples) == 0 {
		return nil
	}
	log.Debugf("Received %d oomprof samples for PID %d, comm: %s", len(memSamples), meta.PID, meta.Comm)

	pid := libpf.PID(meta.PID)
	comm := libpf.Intern(meta.Comm)
	labelResult := r.lbls.labelsForTID(pid, pid, comm, 0, support.TraceOriginUnknown, nil)
	if !labelResult.keep {
		r.counters.skippedByRelabeling.Inc()
		log.Debugf("Skipping %d memory traces for PID %d, filtered by relabeling", len(memSamples), meta.PID)
		return nil
	}

	// Intern the per-process attributes once for the whole batch.
	buildID := libpf.Intern(meta.BuildID)
	execPath := libpf.Intern(meta.ExecutablePath)
	var customLabels map[libpf.String]libpf.String
	if len(meta.CustomLabels) > 0 {
		customLabels = make(map[libpf.String]libpf.String, len(meta.CustomLabels))
		for k, v := range meta.CustomLabels {
			customLabels[libpf.Intern(k)] = libpf.Intern(v)
		}
	}

	traceEventMeta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(meta.Timestamp),
		Comm:           comm,
		ProcessName:    libpf.Intern(meta.ProcessName),
		ExecutablePath: execPath,
		PID:            pid,
	}

	r.sampleWriterV2Mu.Lock()
	defer r.sampleWriterV2Mu.Unlock()

	for i := range memSamples {
		s := &memSamples[i]

		t := &libpf.Trace{CustomLabels: customLabels}
		for _, addr := range s.Addresses {
			t.Frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: libpf.AddressOrLineno(addr),
				FunctionName:    buildID,  // Stash the BuildID for the location builder.
				SourceFile:      execPath, // Stash the executable path.
			})
		}
		traceHash := traceutil.HashTrace(t)

		if s.Allocs != s.Frees {
			r.writeSampleV2(t, traceHash, traceEventMeta, labelResult,
				int64(s.Allocs-s.Frees), 0, memorySamplePeriod, false,
				"memory", "inuse_objects", "count", "space", "bytes")
		}
		if s.AllocBytes != s.FreeBytes {
			r.writeSampleV2(t, traceHash, traceEventMeta, labelResult,
				int64(s.AllocBytes-s.FreeBytes), 0, memorySamplePeriod, false,
				"memory", "inuse_space", "bytes", "space", "bytes")
		}
		if r.reportAllocs {
			r.writeSampleV2(t, traceHash, traceEventMeta, labelResult,
				int64(s.Allocs), 0, memorySamplePeriod, false,
				"memory", "alloc_objects", "count", "space", "bytes")
			r.writeSampleV2(t, traceHash, traceEventMeta, labelResult,
				int64(s.AllocBytes), 0, memorySamplePeriod, false,
				"memory", "alloc_space", "bytes", "space", "bytes")
		}
		r.counters.memorySamples.Inc()
	}
	return nil
}

// ReportMetrics records metrics.
func (r *arrowReporter) ReportMetrics(ts uint32, ids []uint32, values []int64) {
	r.metrics.ReportMetrics(ts, ids, values)
}

// Stop triggers a graceful shutdown of arrowReporter.
func (r *arrowReporter) Stop() {
	close(r.stopSignal)
	if r.oomState != nil {
		r.oomState.Close()
		r.oomState = nil
	}
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

// New creates a arrowReporter.
// New creates an arrow-backed reporter, v1 or v2 schema per cfg.UseV2Schema.
func New(cfg Config) (ParcaReporter, error) {
	if cfg.OfflineMode != nil && !cfg.DisableSymbolUpload {
		return nil, errors.New("Illogical configuration: offline mode with symbol upload enabled")
	}

	shared, err := newSharedReporterParts(cfg)
	if err != nil {
		return nil, err
	}

	stacks, err := lru.NewSynced[libpf.TraceHash, libpf.Frames](cfg.CacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	var loggedStacks *lru.SyncedLRU[libpf.TraceHash, struct{}]
	if cfg.OfflineMode != nil {
		loggedStacks, err = lru.NewSynced[libpf.TraceHash, struct{}](cfg.CacheSize, libpf.TraceHash.Hash32)
		if err != nil {
			return nil, err
		}
	}

	// These count arrow WriteRequest/WriteArrow calls, so they are registered
	// only here. The OTLP backend has no equivalent and registers its own
	// parca_reporter_otlp_* counters instead.
	sampleWrites := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sample_writes_total",
		Help: "the total number of samples written in WriteRequest calls for sample records",
	})
	sampleWriteRequestBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sample_write_request_bytes",
		Help: "the total number of bytes written in WriteRequest calls for sample records",
	})
	stacktraceWriteRequestBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "stacktrace_write_request_bytes",
		Help: "the total number of bytes written in WriteRequest calls for stacktrace records",
	})
	writeRequestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "parca_agent_write_requests_total",
		Help: "Total number of WriteArrow requests to the Parca backend after retry interceptor processing, labeled by terminal gRPC status code (code=\"OK\" indicates a successful write).",
	}, []string{"code"})

	cfg.Registerer.MustRegister(sampleWriteRequestBytes)
	cfg.Registerer.MustRegister(sampleWrites)
	cfg.Registerer.MustRegister(stacktraceWriteRequestBytes)
	cfg.Registerer.MustRegister(writeRequestsTotal)

	// Initialize sample writer based on schema version
	var sampleWriter *SampleWriter
	var sampleWriterV2 *SampleWriterV2
	if cfg.UseV2Schema {
		sampleWriterV2 = NewSampleWriterV2(cfg.Mem)
	} else {
		sampleWriter = NewSampleWriter(cfg.Mem)
	}

	r := &arrowReporter{
		stopSignal:                  make(chan libpf.Void),
		client:                      cfg.ProfileStoreClient,
		executables:                 shared.executables,
		lbls:                        shared.labeler,
		execs:                       shared.execs,
		metrics:                     shared.metrics,
		counters:                    shared.counters,
		logProvider:                 shared.logProvider,
		tracerProvider:              shared.tracerProvider,
		sampleWriter:                sampleWriter,
		useV2Schema:                 cfg.UseV2Schema,
		mergeGpuProfiles:            cfg.MergeGpuProfiles,
		sampleWriterV2:              sampleWriterV2,
		stacks:                      stacks,
		mem:                         cfg.Mem,
		externalLabels:              cfg.ExternalLabels,
		samplesPerSecond:            cfg.SamplesPerSecond,
		disableSymbolUpload:         cfg.DisableSymbolUpload,
		reportInterval:              cfg.ReportInterval,
		nodeName:                    cfg.NodeName,
		reportAllocs:                cfg.EnableOOMProfAllocs,
		sampleWrites:                sampleWrites,
		sampleWriteRequestBytes:     sampleWriteRequestBytes,
		stacktraceWriteRequestBytes: stacktraceWriteRequestBytes,
		writeRequestsTotal:          writeRequestsTotal,
		offlineModeConfig:           cfg.OfflineMode,
		offlineModeLoggedStacks:     loggedStacks,
	}

	if cfg.EnableOOMProf {
		state, err := setupOOMProf(cfg, newOOMProfAdapter(r))
		if err != nil {
			close(r.stopSignal)
			return nil, err
		}
		r.oomState = state
		// The labeler stamps job="oomprof" off this, and it can only be
		// wired after SetupWithReporter returns.
		shared.labeler.SetOOMState(state)
	}

	return r, nil
}

const (
	DATA_FILE_EXTENSION            string = ".padata"
	DATA_FILE_COMPRESSED_EXTENSION string = ".padata.zst"
)

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
	compressedLog, err := os.OpenFile(compressedFpath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o660)
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
	file, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o660)
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

func (r *arrowReporter) rotateOfflineModeLog() error {
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

func (r *arrowReporter) runOfflineModeRotation(ctx context.Context) error {
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

func (r *arrowReporter) Start(mainCtx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	go func() {
		if err := r.execs.Run(ctx); err != nil {
			log.Fatalf("Running symbol uploader failed: %v", err)
		}
	}()

	if r.offlineModeConfig != nil {
		if err := os.MkdirAll(r.offlineModeConfig.StoragePath, 0o770); err != nil {
			// Cancel before returning, or the uploader goroutine above
			// outlives the failed Start with a live context.
			cancelReporting()
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

	// The SDK BatchProcessor owns its own goroutines from NewBatchProcessor
	// time, so we don't start anything here. We do need to ensure the
	// provider is flushed and closed when the reporter shuts down.
	if r.logProvider != nil {
		go func() {
			<-ctx.Done()
			// Use a fresh context with a short deadline so a stuck export
			// can't block teardown indefinitely.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.logProvider.Shutdown(shutdownCtx); err != nil {
				log.Warnf("OTLP logs provider shutdown: %v", err)
			}
		}()
	}
	if r.tracerProvider != nil {
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.tracerProvider.Shutdown(shutdownCtx); err != nil {
				log.Warnf("OTLP traces provider shutdown: %v", err)
			}
		}()
	}

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	go func() {
		<-r.stopSignal
		cancelReporting()
	}()

	return nil
}

func (r *arrowReporter) logDataForOfflineMode(ctx context.Context, buf *bytes.Buffer) error {
	// Dispatch to v2 path if enabled
	if r.useV2Schema {
		return r.logDataForOfflineModeV2(ctx, buf)
	}

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

	r.sampleWrites.Add(float64(record.NumRows()))
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
func (r *arrowReporter) reportDataToBackend(ctx context.Context, buf *bytes.Buffer) error {
	// Dispatch to v2 path if enabled
	if r.useV2Schema {
		return r.reportDataToBackendV2(ctx, buf)
	}

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

	log.Debugf("Sending profile with %d samples (%d bytes)", record.NumRows(), buf.Len())

	client, err := r.client.Write(ctx)
	if err != nil {
		return err
	}
	defer client.CloseSend()

	if err := client.Send(&profilestorepb.WriteRequest{
		Record: buf.Bytes(),
	}); err != nil {
		return err
	}

	r.sampleWrites.Add(float64(record.NumRows()))
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

	// CloseSend() is deferred at the top of this function.
	// Drain any remaining responses so the gRPC helper goroutine
	// (newClientStreamWithParams.func4) can exit.
	for {
		_, err := client.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *arrowReporter) writeCommonLabels(w *SampleWriter, rows uint64) {
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
func (r *arrowReporter) buildSampleRecord(ctx context.Context) (arrow.Record, int) {
	newWriter := NewSampleWriter(r.mem)

	r.sampleWriterMu.Lock()
	w := r.sampleWriter
	r.sampleWriter = newWriter
	r.sampleWriterMu.Unlock()

	defer w.Release()

	// Completing the record with all values that are the same for all rows.
	rows := uint64(w.Value.Len())
	r.writeCommonLabels(w, rows)

	return w.NewRecord(), len(w.labelBuilders)
}

func (r *arrowReporter) buildStacktraceRecord(ctx context.Context, stacktraceIDs *array.Binary) (arrow.Record, error) {
	w := NewLocationsWriter(r.mem)
	for i := 0; i < stacktraceIDs.Len(); i++ {
		isComplete := true

		traceHash, err := libpf.TraceHashFromBytes(stacktraceIDs.Value(i))
		if err != nil {
			return nil, err
		}

		traceInfo, exists := r.stacks.Get(traceHash)
		if !exists {
			w.LocationsList.Append(true)
			w.Locations.Append(true)
			w.Address.Append(0)
			w.FrameType.AppendString(libpf.UnknownFrame.String())
			w.MappingFile.AppendNull()
			w.MappingBuildID.AppendNull()
			w.Lines.Append(true)
			w.Line.Append(true)
			w.LineNumber.Append(int64(0))
			w.ColumnNumber.Append(uint64(0))
			w.FunctionName.AppendString("missing stacktrace")
			w.FunctionSystemName.AppendString("")
			w.FunctionFilename.AppendNull()
			w.FunctionStartLine.Append(0)
			w.IsComplete.Append(false)
			continue
		}

		// Walk every frame of the trace.
		if len(traceInfo) == 0 {
			w.LocationsList.Append(false)
		} else {
			w.LocationsList.Append(true)
		}
		for _, frameHandle := range traceInfo {
			frame := frameHandle.Value()
			w.Locations.Append(true)
			w.Address.Append(uint64(frame.AddressOrLineno))

			if frame.Type.IsAbort() {
				w.FrameType.AppendString(frame.Type.String())

				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
				w.MappingFile.AppendString("agent-internal-error-frame")
				w.MappingBuildID.AppendNull()
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(int64(0))
				w.ColumnNumber.Append(uint64(0))
				w.FunctionName.AppendString("aborted")
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendNull()
				w.FunctionStartLine.Append(0)
				continue
			}
			switch frameKind := frame.Type; frameKind {
			case libpf.NativeFrame:
				w.FrameType.AppendString(frame.Type.String())

				var execInfo *metadata.ExecInfo
				var fid libpf.FileID

				if frame.Mapping.Valid() {
					m := frame.Mapping.Value()
					fileValid := m.File != libpf.FrameMappingFile{}
					if fileValid {
						mf := m.File.Value()
						fid = mf.FileID
						// As native frames are resolved in the backend, we use Mapping to
						// report these frames.

						if ei, exists := r.executables.Get(mf.FileID); exists {
							execInfo = &ei
						}
					}
				}

				if execInfo != nil {
					w.MappingFile.AppendString(execInfo.FileName)

					if execInfo.BuildID != "" {
						w.MappingBuildID.AppendString(execInfo.BuildID)
					} else {
						w.MappingBuildID.AppendString(fid.StringNoQuotes())
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
				w.FrameType.AppendString(frame.Type.String())

				var execInfo *metadata.ExecInfo
				if frame.Mapping.Valid() {
					m := frame.Mapping.Value()
					fileValid := m.File != libpf.FrameMappingFile{}
					if fileValid {
						mf := m.File.Value()
						if ei, exists := r.executables.Get(mf.FileID); exists {
							execInfo = &ei
						}
					}
				}
				var moduleName string
				if execInfo != nil {
					moduleName = execInfo.FileName
				} else {
					moduleName = "vmlinux"
				}

				// Use the frame metadata directly
				var symbol string
				var lineNumber int64
				if frame.FunctionName.String() != "" {
					symbol = frame.FunctionName.String()
					lineNumber = int64(frame.SourceLine)
				} else {
					// Fallback when no frame metadata is available
					symbol = "UNKNOWN"
					isComplete = false
				}
				w.MappingBuildID.AppendNull()
				w.FunctionFilename.AppendString(moduleName)
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(lineNumber)
				w.ColumnNumber.Append(uint64(frame.SourceColumn))
				w.FunctionName.AppendString(symbol)
				w.FunctionSystemName.AppendString("")
				w.MappingFile.AppendString("[kernel.kallsyms]")
				w.FunctionStartLine.Append(0)
			case libpf.CUDAPCFrame:
				// CUDA PC sample: one mapping per cubin (build_id = cubin CRC
				// FileID). The kernel's mangled name rides as the system name of a
				// placeholder line (line 0, no function name); the backend resolves
				// the source line per function, gated on the "cuda-pc" frame type.
				w.FrameType.AppendString(frame.Type.String())

				var fid libpf.FileID
				if frame.Mapping.Valid() {
					mf := frame.Mapping.Value().File.Value()
					fid = mf.FileID
					w.MappingFile.AppendString(mf.FileName.String())
				} else {
					w.MappingFile.AppendNull()
				}
				w.MappingBuildID.AppendString(fid.StringNoQuotes())

				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(0)
				w.ColumnNumber.Append(0)
				w.FunctionName.AppendNull()
				w.FunctionSystemName.AppendString(frame.FunctionName.String())
				w.FunctionFilename.AppendNull()
				w.FunctionStartLine.Append(0)

			default:
				w.FrameType.AppendString(frame.Type.String())

				// Use the frame metadata directly
				var (
					lineNumber   int64
					functionName string
					filePath     string
				)

				if frame.FunctionName.String() != "" {
					functionName = frame.FunctionName.String()
					filePath = frame.SourceFile.String()
					lineNumber = int64(frame.SourceLine)
				} else {
					// Fallback when no frame metadata is available
					functionName = "UNREPORTED"
					filePath = "UNREPORTED"
					isComplete = false
				}
				// empty path causes the backend to crash
				if filePath == "" {
					filePath = "UNKNOWN"
				}
				w.MappingFile.AppendNull()
				if frame.Mapping.Valid() && frame.Mapping.Value().File.Value().GnuBuildID != "" {
					w.MappingBuildID.AppendString(frame.Mapping.Value().File.Value().GnuBuildID)
				} else {
					w.MappingBuildID.AppendNull()
				}
				w.Lines.Append(true)
				w.Line.Append(true)
				w.LineNumber.Append(lineNumber)
				w.ColumnNumber.Append(uint64(frame.SourceColumn))
				w.FunctionName.AppendString(functionName)
				w.FunctionSystemName.AppendString("")
				w.FunctionFilename.AppendString(filePath)
				w.FunctionStartLine.Append(0)
			}
		}

		w.IsComplete.Append(isComplete)
	}

	return w.NewRecord(stacktraceIDs), nil
}

// buildSampleRecordV2 builds an Arrow record using the v2 schema with inline stacktraces.
func (r *arrowReporter) buildSampleRecordV2(ctx context.Context) arrow.Record {
	newWriter := NewSampleWriterV2(r.mem)

	r.sampleWriterV2Mu.Lock()
	w := r.sampleWriterV2
	r.sampleWriterV2 = newWriter
	r.sampleWriterV2Mu.Unlock()

	defer w.Release()

	// Complete the record with all values that are the same for all rows
	rows := uint64(w.Value.Len())
	r.writeCommonLabelsV2(w, rows)

	return w.NewRecord()
}

// writeCommonLabelsV2 writes common labels to all rows in the v2 writer.
func (r *arrowReporter) writeCommonLabelsV2(w *SampleWriterV2, rows uint64) {
	for _, label := range r.externalLabels {
		w.LabelAll(label.Name, label.Value)
	}
}

// logDataForOfflineModeV2 logs data for offline mode using the v2 schema.
// V2 records are self-contained, so no separate stacktrace record is needed.
func (r *arrowReporter) logDataForOfflineModeV2(ctx context.Context, buf *bytes.Buffer) error {
	record := r.buildSampleRecordV2(ctx)
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
		return fmt.Errorf("failed to write v2 samples: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close v2 samples writer: %w", err)
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
		return fmt.Errorf("failed to write to log %s: %v", r.offlineModeLogPath, err)
	}

	r.sampleWrites.Add(float64(record.NumRows()))
	r.sampleWriteRequestBytes.Add(float64(buf.Len()))

	// V2 records are self-contained, no separate stacktrace record needed
	// We need to fsync before updating the number of records at the head of the file
	if err := r.offlineModeLogFile.Sync(); err != nil {
		return fmt.Errorf("failed to fsync log %s: %v", r.offlineModeLogPath, err)
	}

	r.offlineModeNBatchesInCurrentFile += 1
	n := r.offlineModeNBatchesInCurrentFile
	log.Debugf("wrote v2 batch %d", n)

	if _, err := r.offlineModeLogFile.WriteAt([]byte{byte(n / 256), byte(n)}, 6); err != nil {
		return fmt.Errorf("failed to write to log %s: %v", r.offlineModeLogPath, err)
	}

	return nil
}

// reportDataToBackendV2 sends a v2 schema record to the backend.
// V2 records are self-contained with inline stacktraces, so no back-and-forth is needed.
func (r *arrowReporter) reportDataToBackendV2(ctx context.Context, buf *bytes.Buffer) error {
	record := r.buildSampleRecordV2(ctx)
	defer record.Release()

	if record.NumRows() == 0 {
		log.Debugf("Skip sending of v2 profile with no samples")
		return nil
	}

	buf.Reset()
	w := ipc.NewWriter(buf,
		ipc.WithSchema(record.Schema()),
		ipc.WithAllocator(r.mem),
		ipc.WithLZ4(),
	)

	if err := w.Write(record); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	if _, err := r.client.WriteArrow(ctx, &profilestorepb.WriteArrowRequest{
		IpcBuffer: buf.Bytes(),
	}); err != nil {
		r.writeRequestsTotal.WithLabelValues(status.Code(err).String()).Inc()
		return err
	}
	r.writeRequestsTotal.WithLabelValues(codes.OK.String()).Inc()

	r.sampleWrites.Add(float64(record.NumRows()))
	r.sampleWriteRequestBytes.Add(float64(buf.Len()))

	log.Debugf("Sent v2 profile with %d samples", record.NumRows())

	return nil
}
