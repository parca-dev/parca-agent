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
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
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
	"google.golang.org/grpc"
)

// otlpProfilesReporter ships profiles as OTLP/profiles over gRPC.
//
// It is a peer of arrowReporter, not a wrapper around the upstream OTLP
// reporter. Upstream's converter cannot represent two of the three profile
// kinds this agent produces: memory profiles need four sample types from one
// call (pprofile.Profile carries exactly one) and arrive on frames whose build
// ID is stashed in FunctionName, and GPU origins are rejected before the
// encoding is reached. Both limits live behind reporter/internal/pdata, which
// is unimportable. So the conversion is ours -- see pprofile.go -- and this
// type is the reporter around it.
type otlpProfilesReporter struct {
	client pprofileotlp.GRPCClient
	// exportOpts carries the transport compressor, if any. gRPC negotiates
	// compression per call by codec name, so it is applied here rather than
	// on the dial -- the arrow paths share this connection and already
	// compress inside their own payload.
	exportOpts []grpc.CallOption

	builder   *pprofileBuilder
	builderMu sync.Mutex
	// windowStart is the beginning of the batch currently accumulating.
	windowStart time.Time

	labeler  *processLabeler
	execs    *execTracker
	metrics  *metricsBridge
	counters *reporterCounters

	logProvider    *sdklog.LoggerProvider
	tracerProvider *sdktrace.TracerProvider

	samplesPerSecond int64
	mergeGpuProfiles bool
	reportInterval   time.Duration
	reportAllocs     bool

	oomState *oomprof.State

	exportedSamples prometheus.Counter
	exportFailures  prometheus.Counter
	exportedBytes   prometheus.Counter

	stopSignal chan libpf.Void
}

var _ ParcaReporter = (*otlpProfilesReporter)(nil)

// NewOTLPProfiles builds a reporter that converts trace and memory events into
// OTLP/profiles and ships them over conn.
//
// conn carries profiles only. Debuginfo upload, agent logs, and agent traces
// each have their own destination and are supplied through cfg.
func NewOTLPProfiles(cfg Config, conn *grpc.ClientConn) (ParcaReporter, error) {
	if conn == nil {
		return nil, errors.New("OTLP profiles reporter requires a gRPC connection")
	}
	if cfg.OfflineMode != nil {
		return nil, errors.New("offline mode is not supported by the OTLP profiles exporter")
	}

	shared, err := newSharedReporterParts(cfg)
	if err != nil {
		return nil, err
	}

	exportedSamples := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "parca_reporter_otlp_exported_samples_total",
		Help: "Total number of samples successfully exported as OTLP/profiles.",
	})
	exportFailures := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "parca_reporter_otlp_export_failures_total",
		Help: "Total number of failed OTLP/profiles export requests. A failure drops the batch.",
	})
	exportedBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "parca_reporter_otlp_exported_bytes_total",
		Help: "Total uncompressed OTLP/profiles bytes handed to gRPC. Transport compression happens below this, so compare against the connection's own byte counters to see what --remote-store-compression saved.",
	})
	cfg.Registerer.MustRegister(exportedSamples)
	cfg.Registerer.MustRegister(exportFailures)
	cfg.Registerer.MustRegister(exportedBytes)

	r := &otlpProfilesReporter{
		client:           pprofileotlp.NewGRPCClient(conn),
		builder:          newPprofileBuilder(shared.executables, cfg.NodeName),
		labeler:          shared.labeler,
		execs:            shared.execs,
		metrics:          shared.metrics,
		counters:         shared.counters,
		logProvider:      shared.logProvider,
		tracerProvider:   shared.tracerProvider,
		samplesPerSecond: cfg.SamplesPerSecond,
		mergeGpuProfiles: cfg.MergeGpuProfiles,
		reportInterval:   cfg.ReportInterval,
		reportAllocs:     cfg.EnableOOMProfAllocs,
		exportOpts:       cfg.ExportCallOptions,
		exportedSamples:  exportedSamples,
		exportFailures:   exportFailures,
		exportedBytes:    exportedBytes,
		stopSignal:       make(chan libpf.Void),
	}

	if cfg.EnableOOMProf {
		state, err := setupOOMProf(cfg, newOOMProfAdapter(r))
		if err != nil {
			close(r.stopSignal)
			return nil, err
		}
		r.oomState = state
		r.labeler.SetOOMState(state)
	}

	return r, nil
}

func (r *otlpProfilesReporter) SetProbes(p ProbesHook) { r.execs.probes = p }

func (r *otlpProfilesReporter) Logger(scope string) otellog.Logger {
	return logger(r.logProvider, scope)
}

func (r *otlpProfilesReporter) Tracer(scope string) oteltrace.Tracer {
	return tracer(r.tracerProvider, scope)
}

func (r *otlpProfilesReporter) ExecutableKnown(fileID libpf.FileID) bool {
	return r.execs.ExecutableKnown(fileID)
}

func (r *otlpProfilesReporter) ReportExecutable(args *reporter.ExecutableMetadata) {
	r.execs.ReportExecutable(args)
}

func (r *otlpProfilesReporter) ReportMetrics(ts uint32, ids []uint32, values []int64) {
	r.metrics.ReportMetrics(ts, ids, values)
}

// ReportFramesForTrace is a NOP; frames arrive inline on the trace.
func (r *otlpProfilesReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP; counts arrive inline on the trace meta.
func (r *otlpProfilesReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *samples.TraceEventMeta) {
}

func (r *otlpProfilesReporter) SupportsReportTraceEvent() bool { return true }

// ReportHostMetadata is a NOP, matching the arrow backends.
func (r *otlpProfilesReporter) ReportHostMetadata(_ map[string]string) {}

// ReportHostMetadataBlocking is a NOP, matching the arrow backends.
func (r *otlpProfilesReporter) ReportHostMetadataBlocking(_ context.Context,
	_ map[string]string, _ int, _ time.Duration,
) error {
	return nil
}

// ReportTraceEvent converts one trace event into a pprofile sample.
//
// Unlike the arrow paths there is no schema branch: every origin the tracer can
// produce has a sample type here, including the CUDA and GPU-PC origins that
// upstream's converter rejects outright.
func (r *otlpProfilesReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta,
) error {
	labelResult := r.labeler.labelsForTID(meta.TID, meta.PID, meta.Comm, meta.CPU, meta.Origin, meta.EnvVars)
	if !labelResult.keep {
		r.counters.skippedByRelabeling.Inc()
		log.Debugf("Skipping trace event for PID %d, as it was filtered out by relabeling", meta.PID)
		return nil
	}

	if len(trace.Frames) == 0 {
		r.counters.emptySamples.Inc()
	}

	res := resourceLabels{
		Labels:         labelResult.resource,
		PID:            int64(meta.PID),
		ExecutablePath: meta.ExecutablePath.String(),
		ContainerID:    meta.ContainerID.String(),
		ServiceName:    serviceNameFor(meta.APMServiceName, meta.Comm, meta.ExecutablePath),
	}

	s := sampleData{
		Frames:       trace.Frames,
		TraceHash:    traceutil.HashTrace(trace),
		Timestamp:    uint64(meta.Timestamp),
		SampleLabels: labelResult.sample,
		CustomLabels: trace.CustomLabels,
	}

	var st sampleType
	switch meta.Origin {
	case support.TraceOriginSampling:
		// One observation per tick; the tick length rides in the period,
		// exactly as the arrow path does.
		st, s.Value = cpuSampleType(r.samplesPerSecond), 1
		r.counters.cpuSamples.Inc()
	case support.TraceOriginOffCPU:
		st, s.Value = offCPUSampleType, meta.Value
		r.counters.offcpuSamples.Inc()
	case support.TraceOriginProbe:
		st, s.Value = probeSampleType, meta.Value
		r.counters.probeSamples.Inc()
	case support.TraceOriginCuda:
		s.Value = meta.Value
		if r.mergeGpuProfiles {
			st = gpuMergedSampleType
			s.ExtraAttrs = map[string]string{"gpu_view": "kernel_time"}
		} else {
			st = gpuKernelSampleType
		}
		r.counters.gpuSamples.Inc()
	case support.TraceOriginGpuPC:
		nsPerSample := gpuNsPerSample(meta.PID)
		if r.mergeGpuProfiles {
			// The merged view is in nanoseconds, so convert the raw count
			// inline; the non-merged view keeps the honest sample count
			// and carries the weight in the period.
			s.Value = meta.Value
			if nsPerSample > 0 {
				s.Value *= nsPerSample
			}
			st = gpuMergedSampleType
			s.ExtraAttrs = map[string]string{"gpu_view": "pc_sample"}
		} else {
			st, s.Value = gpuPCSampleType(nsPerSample), meta.Value
		}
		r.counters.gpuPCSamples.Inc()
	default:
		log.Warnf("unknown trace origin: %d", meta.Origin)
		return nil
	}

	r.builderMu.Lock()
	defer r.builderMu.Unlock()
	r.builder.AddSample(res, st, s)
	return nil
}

// ReportMemoryTraces emits the inuse and, when enabled, alloc axes for a batch
// of memory-attributed traces. All samples share one process snapshot, so
// labels are resolved once and the builder lock is taken once.
//
// Each axis is its own sample type and therefore its own OTLP Profile. That is
// the structural reason this backend cannot delegate to upstream's converter:
// it builds one Profile per origin, with one sample type in it.
func (r *otlpProfilesReporter) ReportMemoryTraces(
	memSamples []oomprof.Sample, meta oomprof.SampleMeta,
) error {
	if len(memSamples) == 0 {
		return nil
	}
	log.Debugf("Received %d oomprof samples for PID %d, comm: %s", len(memSamples), meta.PID, meta.Comm)

	pid := libpf.PID(meta.PID)
	comm := libpf.Intern(meta.Comm)
	labelResult := r.labeler.labelsForTID(pid, pid, comm, 0, support.TraceOriginUnknown, nil)
	if !labelResult.keep {
		r.counters.skippedByRelabeling.Inc()
		log.Debugf("Skipping %d memory traces for PID %d, filtered by relabeling", len(memSamples), meta.PID)
		return nil
	}

	var customLabels map[libpf.String]libpf.String
	if len(meta.CustomLabels) > 0 {
		customLabels = make(map[libpf.String]libpf.String, len(meta.CustomLabels))
		for k, v := range meta.CustomLabels {
			customLabels[libpf.Intern(k)] = libpf.Intern(v)
		}
	}

	res := resourceLabels{
		Labels:         labelResult.resource,
		PID:            int64(meta.PID),
		ExecutablePath: meta.ExecutablePath,
		ServiceName: serviceNameFor(meta.ProcessName, comm,
			libpf.Intern(meta.ExecutablePath)),
	}

	r.builderMu.Lock()
	defer r.builderMu.Unlock()

	for i := range memSamples {
		s := &memSamples[i]

		t := &libpf.Trace{CustomLabels: customLabels}
		for _, addr := range s.Addresses {
			t.Frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: libpf.AddressOrLineno(addr),
			})
		}

		base := sampleData{
			Frames:       t.Frames,
			TraceHash:    traceutil.HashTrace(t),
			Timestamp:    uint64(meta.Timestamp),
			SampleLabels: labelResult.sample,
			CustomLabels: customLabels,
			// The build ID and executable path travel beside the frames
			// rather than on them, so the converter does not mistake them
			// for a resolved function name and file.
			SyntheticMemoryFrames: true,
			MemoryBuildID:         meta.BuildID,
			MemoryExecPath:        meta.ExecutablePath,
		}

		add := func(st sampleType, value int64) {
			sd := base
			sd.Value = value
			r.builder.AddSample(res, st, sd)
		}

		if s.Allocs != s.Frees {
			add(memInuseObjects, int64(s.Allocs-s.Frees))
		}
		if s.AllocBytes != s.FreeBytes {
			add(memInuseSpace, int64(s.AllocBytes-s.FreeBytes))
		}
		if r.reportAllocs {
			add(memAllocObjects, int64(s.Allocs))
			add(memAllocSpace, int64(s.AllocBytes))
		}
		r.counters.memorySamples.Inc()
	}
	return nil
}

func (r *otlpProfilesReporter) Start(mainCtx context.Context) error {
	ctx, cancelReporting := context.WithCancel(mainCtx)

	r.windowStart = time.Now()

	go func() {
		if err := r.execs.Run(ctx); err != nil {
			log.Fatalf("Running symbol uploader failed: %v", err)
		}
	}()

	go func() {
		tick := time.NewTicker(r.reportInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.flush(ctx); err != nil {
					log.Errorf("OTLP profiles export failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(r.reportInterval, 0.2))
			}
		}
	}()

	shutdownProviders(ctx, r.logProvider, r.tracerProvider)

	go func() {
		<-r.stopSignal
		cancelReporting()
	}()

	return nil
}

// flush swaps out the accumulated batch and exports it. The builder lock is
// held only for the swap, never across the network call.
func (r *otlpProfilesReporter) flush(ctx context.Context) error {
	r.builderMu.Lock()
	if r.builder.SampleCount() == 0 {
		r.builderMu.Unlock()
		log.Debugf("Skip sending of OTLP profile with no samples")
		return nil
	}
	start, end := r.windowStart, time.Now()
	r.windowStart = end
	count := r.builder.SampleCount()
	profiles := r.builder.Build(start, end)
	r.builderMu.Unlock()

	req := pprofileotlp.NewExportRequestFromProfiles(profiles)
	if pb, mErr := req.MarshalProto(); mErr == nil {
		r.exportedBytes.Add(float64(len(pb)))
	}

	resp, err := r.client.Export(ctx, req, r.exportOpts...)
	if err != nil {
		r.exportFailures.Inc()
		return fmt.Errorf("export %d samples: %w", count, err)
	}
	if ps := resp.PartialSuccess(); ps.ErrorMessage() != "" {
		log.Warnf("OTLP profiles partial success: %s", ps.ErrorMessage())
	}

	r.exportedSamples.Add(float64(count))
	log.Debugf("Sent OTLP profile with %d samples", count)
	return nil
}

func (r *otlpProfilesReporter) Stop() {
	close(r.stopSignal)
	if r.oomState != nil {
		r.oomState.Close()
		r.oomState = nil
	}
}

// gpuNsPerSample returns the nanoseconds of GPU time attributable to one PC
// sample observation, or 0 if the per-pid GpuConfig has not arrived yet.
func gpuNsPerSample(pid libpf.PID) int64 {
	cfg, ok := gpu.LoadGpuConfig(uint32(pid))
	if !ok {
		gpu.WarnMissingGpuConfig(uint32(pid))
		return 0
	}
	return cfg.NsPerSample()
}

// serviceNameFor picks the service.name for a profiled process.
//
// OTLP has no other place to name a resource, and consumers key resource
// identity on it -- Dash0's resource-extractor, for one, falls back to a bare
// hash without it, which makes every profiled process anonymous in the UI. But
// APMServiceName is only set for APM-instrumented processes, so relying on it
// alone leaves the attribute absent for most of what a system profiler sees.
//
// The order is deliberate:
//   - apmName wins when present: the process named itself, so respect it.
//   - comm next: always available, and it is what top and ps show, so it
//     matches what an operator already calls the process. The kernel truncates
//     it to 15 characters (TASK_COMM_LEN-1), which is cosmetic.
//   - the executable's basename last: never truncated, but wrong for
//     interpreters, where every service would collapse into "python3".
func serviceNameFor(apmName string, comm libpf.String, execPath libpf.String) string {
	if apmName != "" {
		return apmName
	}
	if c := comm.String(); c != "" {
		return c
	}
	if p := execPath.String(); p != "" {
		return path.Base(p)
	}
	return ""
}
