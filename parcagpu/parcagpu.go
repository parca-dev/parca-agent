// Package parcagpu reads GPU events from the eBPF profiler's cupti_events
// ringbuf, marries them with symbolized CUDA stack traces from the profiler's
// interpreter/gpu package, and reports the completed traces directly via a
// TraceReporter. It is wired into the profiler through
// processmanager.TraceInterceptor.
//
// Every event in the ringbuf begins with a u32 event_type discriminator at
// offset 0; the reader loop dispatches by tag to handlers for kernel timing,
// cubin-loaded notifications, PC samples, stall-reason maps, and BPF errors.
package parcagpu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

// Start starts a goroutine that reads GPU events from the cupti_events ringbuf
// and returns a TraceInterceptor that diverts CUDA traces (post-symbolization)
// into the GPU fixer. Completed CUDA traces are reported directly via rep.
// Cubin-loaded events are forwarded to exeRep for debug-file upload; if exeRep
// is nil the cubin is still cached locally for PC-sample symbolization.
func Start(ctx context.Context, tr *tracer.Tracer,
	rep reporter.TraceReporter, exeRep reporter.ExecutableReporter,
) processmanager.TraceInterceptor {
	cuptiEvents := tr.GetEbpfMaps()["cupti_events"]
	if cuptiEvents == nil {
		log.Warn("[cuda] cupti_events map not present; GPU profiling disabled")
		return func(_ *libpf.Trace, _ *samples.TraceEventMeta) bool {
			return false
		}
	}

	eventReader, err := ringbuf.NewReader(cuptiEvents)
	if err != nil {
		log.Fatalf("Failed to open cupti_events ringbuf: %v", err)
	}

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64
	var cubinCount, pcSampleCount, stallMapCount, errorCount, unknownCount atomic.Uint64

	// processBatch processes a batch of kernel timing events and reports completed traces.
	processBatch := func(batch []gpu.CuptiKernelEvent) {
		outputs := gpu.AddTimes(batch)
		for i := range outputs {
			outputs[i].Trace.Hash = traceutil.HashTrace(outputs[i].Trace)
			if err := rep.ReportTraceEvent(outputs[i].Trace, outputs[i].Meta); err != nil {
				log.Errorf("[parcagpu] failed to report CUDA trace: %v", err)
			}
		}
	}

	const batchSize = 100
	go func() {
		var rec ringbuf.Record
		batch := make([]gpu.CuptiKernelEvent, 0, batchSize)

		logTicker := time.NewTicker(5 * time.Second)
		defer logTicker.Stop()

		clearTicker := time.NewTicker(2 * time.Second)
		defer clearTicker.Stop()

		for {
			select {
			case <-logTicker.C:
				lost := lostEventsCount.Swap(0)
				readErr := readErrorCount.Swap(0)
				noData := noDataCount.Swap(0)
				cubin := cubinCount.Swap(0)
				pcs := pcSampleCount.Swap(0)
				stall := stallMapCount.Swap(0)
				errs := errorCount.Swap(0)
				unknown := unknownCount.Swap(0)
				if lost > 0 || readErr > 0 || noData > 0 || unknown > 0 {
					log.Warnf("[cuda] cupti_events reader: lost=%d readErrors=%d noData=%d unknown=%d",
						lost, readErr, noData, unknown)
				}
				if cubin > 0 || pcs > 0 || stall > 0 || errs > 0 {
					log.Debugf("[cuda] cupti_events: cubin=%d pcSample=%d stallMap=%d errors=%d",
						cubin, pcs, stall, errs)
				}
			case <-clearTicker.C:
				// Periodically clean up all GPU trace fixers and report metrics.
				// MaybeClearAll returns metrics for the caller to report via AddSlice,
				// avoiding duplicate-metric warnings from the metrics system.
				metrics.AddSlice(gpu.MaybeClearAll())
			case <-ctx.Done():
				eventReader.Close()
				return
			default:
				if err := eventReader.ReadInto(&rec); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					readErrorCount.Add(1)
					continue
				}
				// Ringbuf has no per-record LostSamples — the producer drops
				// directly when reserve fails.
				if len(rec.RawSample) < 4 {
					noDataCount.Add(1)
					continue
				}

				// Peek the event_type discriminator at offset 0.
				eventType := binary.NativeEndian.Uint32(rec.RawSample[:4])
				switch eventType {
				case gpu.EventTypeKernel:
					if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiKernelEvent{})) {
						noDataCount.Add(1)
						continue
					}
					ev := (*gpu.CuptiKernelEvent)(unsafe.Pointer(&rec.RawSample[0]))
					batch = append(batch, *ev)
					if len(batch) >= batchSize {
						go processBatch(batch)
						batch = make([]gpu.CuptiKernelEvent, 0, batchSize)
					}
				case gpu.EventTypeCubinLoaded:
					cubinCount.Add(1)
					if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiCubinEvent{})) {
						noDataCount.Add(1)
						continue
					}
					ev := (*gpu.CuptiCubinEvent)(unsafe.Pointer(&rec.RawSample[0]))
					go handleCubinLoaded(*ev, exeRep)
				case gpu.EventTypePCSample:
					pcSampleCount.Add(1)
					if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiPCSampleEvent{})) {
						noDataCount.Add(1)
						continue
					}
					ev := *(*gpu.CuptiPCSampleEvent)(unsafe.Pointer(&rec.RawSample[0]))
					go gpu.HandlePCSample(&ev, rep)
				case gpu.EventTypeStallReasonMap:
					stallMapCount.Add(1)
					if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiStallReasonMapEvent{})) {
						noDataCount.Add(1)
						continue
					}
					ev := (*gpu.CuptiStallReasonMapEvent)(unsafe.Pointer(&rec.RawSample[0]))
					count := ev.Count
					if count > 64 {
						count = 64
					}
					names := make([]libpf.String, count)
					for i := uint32(0); i < count; i++ {
						names[i] = libpf.Intern(nullTerm(ev.Names[i][:]))
					}
					gpu.StoreStallReasonMap(ev.Pid, names)
				case gpu.EventTypeError:
					errorCount.Add(1)
					if len(rec.RawSample) >= int(unsafe.Sizeof(gpu.CuptiErrorEvent{})) {
						ev := (*gpu.CuptiErrorEvent)(unsafe.Pointer(&rec.RawSample[0]))
						msg := nullTerm(ev.Message[:])
						comp := nullTerm(ev.Component[:])
						log.Warnf("[cuda] BPF error event: pid=%d code=%d component=%q msg=%q",
							ev.Pid, ev.Code, comp, msg)
					}
				case gpu.EventTypeGpuConfig:
					if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiGpuConfigEvent{})) {
						noDataCount.Add(1)
						continue
					}
					ev := (*gpu.CuptiGpuConfigEvent)(unsafe.Pointer(&rec.RawSample[0]))
					gpu.HandleGpuConfigEvent(ev)
				default:
					unknownCount.Add(1)
				}
			}
		}
	}()

	// Return the interceptor function that diverts CUDA traces post-symbolization.
	// Any traces InterceptTrace returns as already-complete (graph launches, or
	// single launches whose timing arrived early) are reported here directly;
	// traces awaiting timing are retained in the fixer and emitted later from
	// processBatch via AddTimes.
	return func(trace *libpf.Trace, meta *samples.TraceEventMeta) bool {
		if meta.Origin != support.TraceOriginCuda {
			return false
		}
		outputs := gpu.InterceptTrace(trace, meta)
		for i := range outputs {
			outputs[i].Trace.Hash = traceutil.HashTrace(outputs[i].Trace)
			if err := rep.ReportTraceEvent(outputs[i].Trace, outputs[i].Meta); err != nil {
				log.Errorf("[parcagpu] failed to report CUDA trace: %v", err)
			}
		}
		return true
	}
}

func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// handleCubinLoaded reads cubin bytes from process memory, parses the ELF,
// caches metadata for PC sample processing, and reports the cubin to the
// ExecutableReporter for debug file upload.
func handleCubinLoaded(ev gpu.CuptiCubinEvent, exeRep reporter.ExecutableReporter) {
	data, err := gpu.ReadCubinFromProcess(ev.Pid, ev.CubinPtr, ev.CubinSize)
	if err != nil {
		log.Warnf("[cuda] failed to read cubin from pid %d: %v", ev.Pid, err)
		return
	}

	fileID, err := libpf.FileIDFromExecutableReader(bytes.NewReader(data))
	if err != nil {
		log.Warnf("[cuda] failed to compute cubin file ID: %v", err)
		return
	}

	smVersion, texts, err := gpu.ParseCubinELF(data)
	if err != nil {
		log.Warnf("[cuda] failed to parse cubin ELF (crc=0x%x): %v", ev.CubinCRC, err)
		return
	}

	gpu.StoreCubin(&gpu.CubinInfo{
		CRC:       ev.CubinCRC,
		FileID:    fileID,
		SMVersion: smVersion,
		Texts:     texts,
	})

	log.Debugf("[cuda] cubin loaded: crc=0x%x sm=%d texts=%d fileID=%s",
		ev.CubinCRC, smVersion, len(texts), fileID)

	if exeRep == nil {
		return
	}
	cubinName := fmt.Sprintf("cubin-%016x", ev.CubinCRC)
	// GnuBuildID left empty — cubins don't have .note.gnu.build-id. The
	// uploader falls back to BUILD_ID_TYPE_HASH with the FileID, which
	// matches what buildStacktraceRecord sends for the frame.
	mappingFile := libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
		FileID:   fileID,
		FileName: libpf.Intern(cubinName),
	})
	exeRep.ReportExecutable(&reporter.ExecutableMetadata{
		MappingFile: mappingFile,
		Process:     gpu.NewCubinProcess(ev.Pid, data),
		Mapping:     &process.RawMapping{Path: cubinName},
		IsElf:       true,
	})
}
