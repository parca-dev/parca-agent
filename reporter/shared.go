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

// This file holds the parts of a reporter that have nothing to do with the wire
// encoding: the executable/debuginfo tracker, the otel-to-prometheus metrics
// bridge, the shared Prometheus counters, and the logs/traces provider
// accessors. Both the arrow backends and the OTLP backend use them, so
// behaviour cannot drift between the two.

package reporter

import (
	"context"
	"debug/elf"
	"strings"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/xyproto/ainur"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	otelmetrics "go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	otellog "go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/parca-dev/parca-agent/metrics"
	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// execTracker owns everything ReportExecutable touches: the executable
// metadata cache the frame classifier and the main-executable metadata provider
// both read, the debuginfo upload queue, and the probes notification hook.
//
// Symbols always go to the Parca-protocol DebuginfoService regardless of where
// profiles go, so every backend needs one of these.
type execTracker struct {
	executables         *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]
	uploader            *ParcaSymbolUploader
	disableSymbolUpload bool

	// probes is set by SetProbes when the BPF probe service is enabled. When
	// nil the feature is off and ReportExecutable skips the callback.
	probes ProbesHook
}

// Run drives the symbol uploader. A no-op when symbol upload is disabled.
func (t *execTracker) Run(ctx context.Context) error {
	if t.disableSymbolUpload {
		return nil
	}
	return t.uploader.Run(ctx)
}

// ExecutableKnown reports whether the metadata for fileID is already cached.
func (t *execTracker) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := t.executables.Get(fileID)
	return known
}

func (t *execTracker) ReportExecutable(args *reporter.ExecutableMetadata) {
	mf := args.MappingFile.Value()
	if !args.IsElf {
		t.executables.Add(mf.FileID, metadata.ExecInfo{
			FileName: mf.FileName.String(),
			BuildID:  mf.GnuBuildID,
		})
		return
	}

	// Always attempt to upload, the uploader is responsible for deduplication.
	open := func() (process.ReadAtCloser, error) {
		return args.Process.OpenMappingFile(args.Mapping)
	}
	if !t.disableSymbolUpload {
		t.uploader.Upload(context.TODO(), mf.FileID, mf.FileName.String(), mf.GnuBuildID, open)
	}

	if _, exists := t.executables.Get(mf.FileID); exists {
		return
	}

	f, err := open()
	if err != nil {
		log.Debugf("Failed to open file %s: %v", mf.FileName, err)
		return
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		log.Debugf("Failed to open ELF file %s: %v", mf.FileName, err)
		return
	}

	t.executables.Add(mf.FileID, metadata.ExecInfo{
		FileName: mf.FileName.String(),
		BuildID:  mf.GnuBuildID,
		Compiler: ainur.Compiler(ef),
		Static:   ainur.Static(ef),
		Stripped: ainur.Stripped(ef),
	})

	// Prefer the absolute mapping path so probe-config regexes can anchor on
	// a directory; fall back to the basename if Mapping is nil.
	if t.probes != nil {
		path := mf.FileName.String()
		if args.Mapping != nil && args.Mapping.Path != "" {
			path = args.Mapping.Path
		}
		t.probes.OnExecutable(path, mf.FileID)
	}
}

// metricsBridge fans the otel profiler library's metric updates into the
// agent's Prometheus registry. Backend-independent: the metrics describe the
// unwinder, not the export path.
type metricsBridge struct {
	reg     prometheus.Registerer
	metrics map[string]prometheus.Metric
}

func newMetricsBridge(reg prometheus.Registerer) *metricsBridge {
	return &metricsBridge{reg: reg, metrics: make(map[string]prometheus.Metric)}
}

func (b *metricsBridge) ReportMetrics(_ uint32, ids []uint32, values []int64) {
	for i := 0; i < len(ids) && i < len(values); i++ {
		id := ids[i]
		val := values[i]
		field, ok := metrics.AllMetrics[otelmetrics.MetricID(id)]
		if !ok {
			log.Warnf("Unknown metric ID: %d", id)
			continue
		}
		f := strings.Replace(field.Field, ".", "_", -1)

		switch field.Type {
		case metrics.MetricTypeGauge:
			m, ok := b.metrics[f]
			if !ok {
				m = prometheus.NewGauge(prometheus.GaugeOpts{
					Name: f,
					Help: field.Desc,
				})
				b.reg.MustRegister(m.(prometheus.Gauge))
				b.metrics[f] = m
			}
			m.(prometheus.Gauge).Set(float64(val))
		case metrics.MetricTypeCounter:
			m, ok := b.metrics[f]
			if !ok {
				m = prometheus.NewCounter(prometheus.CounterOpts{
					Name: f,
					Help: field.Desc,
				})
				b.reg.MustRegister(m.(prometheus.Counter))
				b.metrics[f] = m
			}
			m.(prometheus.Counter).Add(float64(val))
		default:
			log.Warnf("Unknown metric type: %d", field.Type)
		}
	}
}

// reporterCounters are the metrics that describe sample intake rather than a
// particular wire format, so every backend registers them and `/metrics` keeps
// the same shape across backends.
//
// The arrow-specific write counters (sample_writes_total,
// stacktrace_write_request_bytes, parca_agent_write_requests_total) stay on
// arrowReporter: they count WriteArrow calls, which the OTLP path does not
// make. That does mean those series are absent in OTLP mode.
type reporterCounters struct {
	emptySamples        prometheus.Counter
	skippedByRelabeling prometheus.Counter

	cpuSamples    prometheus.Counter
	gpuSamples    prometheus.Counter
	gpuPCSamples  prometheus.Counter
	offcpuSamples prometheus.Counter
	probeSamples  prometheus.Counter
	memorySamples prometheus.Counter

	debuginfoUploadRequestBytes prometheus.Counter
}

func newReporterCounters(reg prometheus.Registerer) *reporterCounters {
	emptySamples := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "parca_reporter_empty_samples",
		Help: "The number of empty samples reported to the Parca reporter",
	})
	skippedByRelabeling := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "parca_reporter_skipped_by_relabeling",
		Help: "The number of samples skipped due to relabeling rules",
	})
	debuginfoUploadRequestBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "debuginfo_upload_request_bytes",
		Help: "the total number of bytes uploaded in debuginfo upload requests",
	})
	samplesByType := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "parca_reporter_samples_total",
		Help: "Total number of samples by type",
	}, []string{"type"})

	reg.MustRegister(emptySamples)
	reg.MustRegister(skippedByRelabeling)
	reg.MustRegister(debuginfoUploadRequestBytes)
	reg.MustRegister(samplesByType)

	return &reporterCounters{
		emptySamples:                emptySamples,
		skippedByRelabeling:         skippedByRelabeling,
		debuginfoUploadRequestBytes: debuginfoUploadRequestBytes,
		cpuSamples:                  samplesByType.WithLabelValues("cpu"),
		gpuSamples:                  samplesByType.WithLabelValues("gpu"),
		gpuPCSamples:                samplesByType.WithLabelValues("gpu_pc"),
		offcpuSamples:               samplesByType.WithLabelValues("offcpu"),
		probeSamples:                samplesByType.WithLabelValues("probe"),
		memorySamples:               samplesByType.WithLabelValues("memory"),
	}
}

// logger returns a Logger for scope, or a no-op when the provider was never
// built (no destination configured).
func logger(lp *sdklog.LoggerProvider, scope string) otellog.Logger {
	if lp == nil {
		return lognoop.NewLoggerProvider().Logger(scope)
	}
	return lp.Logger(scope)
}

// tracer returns a Tracer for scope, or a no-op when the provider was never
// built. The nil check matters: the arrow reporter's Tracer() promised this in
// its doc comment but did not implement it, so an offline-mode agent with a
// probe config would have panicked here.
func tracer(tp *sdktrace.TracerProvider, scope string) oteltrace.Tracer {
	if tp == nil {
		return tracenoop.NewTracerProvider().Tracer(scope)
	}
	return tp.Tracer(scope)
}
