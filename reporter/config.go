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
	"time"

	debuginfogrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/debuginfo/v1alpha1/debuginfov1alpha1grpc"
	profilestoregrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	lru "github.com/elastic/go-freelru"
	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/relabel"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// Config carries everything any export backend needs.
//
// Fields are grouped by which constructor consumes them.
type Config struct {
	// Shared: labelling, metadata, caches, and metrics.
	ExternalLabels         []Label
	ReportInterval         time.Duration
	LabelTTL               time.Duration
	CacheSize              uint32
	NodeName               string
	AgentRevision          string
	RelabelConfigs         []*relabel.Config
	Registerer             prometheus.Registerer
	SamplesPerSecond       int64
	DisableCPULabel        bool
	DisableThreadIDLabel   bool
	DisableThreadCommLabel bool
	MergeGpuProfiles       bool

	// Symbol upload. Always aimed at a Parca-protocol DebuginfoService,
	// regardless of where profiles go.
	DebuginfoClient         debuginfogrpc.DebuginfoServiceClient
	DisableSymbolUpload     bool
	StripTextSection        bool
	SymbolUploadConcurrency int
	UploaderQueueSize       uint32
	CacheDir                string

	// Logs and traces the agent emits about itself. LogExporter and
	// TraceExporter win when set; otherwise both piggyback GRPCConn.
	GRPCConn      *grpc.ClientConn
	LogExporter   sdklog.Exporter
	TraceExporter sdktrace.SpanExporter

	// oomprof, shared by the arrow and OTLP backends.
	EnableOOMProf       bool
	EnableOOMProfAllocs bool

	// ExportCallOptions are applied to every OTLP profiles export and carry
	// the transport compressor when one is configured. They are per-call
	// rather than dial options because the arrow paths share this connection
	// and already compress inside their own payload.
	ExportCallOptions []grpc.CallOption

	// Arrow-only.
	Mem                memory.Allocator
	ProfileStoreClient profilestoregrpc.ProfileStoreServiceClient
	UseV2Schema        bool
	OfflineMode        *OfflineModeConfig
}

// sharedReporterParts are the backend-independent pieces both constructors
// build the same way. Keeping their construction in one place is what stops the
// two backends from drifting on label semantics or symbol upload.
type sharedReporterParts struct {
	executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]
	labeler     *processLabeler
	execs       *execTracker
	metrics     *metricsBridge
	counters    *reporterCounters

	logProvider    *sdklog.LoggerProvider
	tracerProvider *sdktrace.TracerProvider
}

func newSharedReporterParts(cfg Config) (*sharedReporterParts, error) {
	executables, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	labeler, err := newProcessLabeler(labelerConfig{
		CacheSize:              cfg.CacheSize,
		LabelTTL:               cfg.LabelTTL,
		NodeName:               cfg.NodeName,
		AgentRevision:          cfg.AgentRevision,
		RelabelConfigs:         cfg.RelabelConfigs,
		ExternalLabels:         cfg.ExternalLabels,
		DisableCPULabel:        cfg.DisableCPULabel,
		DisableThreadIDLabel:   cfg.DisableThreadIDLabel,
		DisableThreadCommLabel: cfg.DisableThreadCommLabel,
		Executables:            executables,
	})
	if err != nil {
		return nil, err
	}

	counters := newReporterCounters(cfg.Registerer)

	execs := &execTracker{
		executables:         executables,
		disableSymbolUpload: cfg.DisableSymbolUpload,
	}
	if !cfg.DisableSymbolUpload {
		u, err := NewParcaSymbolUploader(
			cfg.DebuginfoClient,
			cfg.CacheSize,
			cfg.StripTextSection,
			cfg.UploaderQueueSize,
			cfg.SymbolUploadConcurrency,
			cfg.CacheDir,
			counters.debuginfoUploadRequestBytes,
		)
		if err != nil {
			return nil, err
		}
		execs.uploader = u
	}

	lp, tp, err := newProviders(cfg)
	if err != nil {
		return nil, err
	}

	return &sharedReporterParts{
		executables:    executables,
		labeler:        labeler,
		execs:          execs,
		metrics:        newMetricsBridge(cfg.Registerer),
		counters:       counters,
		logProvider:    lp,
		tracerProvider: tp,
	}, nil
}

// newProviders builds the logs and traces providers the agent uses for its own
// telemetry. An explicit exporter wins; otherwise both piggyback the
// remote-store connection, and with neither they stay nil and the accessors
// hand out no-ops.
func newProviders(cfg Config) (*sdklog.LoggerProvider, *sdktrace.TracerProvider, error) {
	opts := providerOptions{
		ServiceName:    "parca-agent",
		ServiceVersion: cfg.AgentRevision,
		HostName:       cfg.NodeName,
	}

	var lp *sdklog.LoggerProvider
	logExp := cfg.LogExporter
	if logExp == nil && cfg.GRPCConn != nil {
		exp, err := newGRPCLogExporter(context.Background(), cfg.GRPCConn)
		if err != nil {
			return nil, nil, err
		}
		logExp = exp
	}
	if logExp != nil {
		lp = newLogProvider(logExp, logProviderOptions(opts))
	}

	var tp *sdktrace.TracerProvider
	traceExp := cfg.TraceExporter
	if traceExp == nil && cfg.GRPCConn != nil {
		exp, err := newGRPCSpanExporter(context.Background(), cfg.GRPCConn)
		if err != nil {
			return nil, nil, err
		}
		traceExp = exp
	}
	if traceExp != nil {
		tp = newTracerProvider(traceExp, tracerProviderOptions(opts))
	}

	return lp, tp, nil
}

// providerOptions is the shared shape of logProviderOptions and
// tracerProviderOptions, which are identical by design.
type providerOptions struct {
	ServiceName    string
	ServiceVersion string
	HostName       string
}

// shutdownProviders registers a ctx.Done() hook that flushes and closes each
// provider, with a short deadline so a stuck export cannot block teardown.
func shutdownProviders(ctx context.Context, lp *sdklog.LoggerProvider, tp *sdktrace.TracerProvider) {
	if lp != nil {
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := lp.Shutdown(shutdownCtx); err != nil {
				log.Warnf("OTLP logs provider shutdown: %v", err)
			}
		}()
	}
	if tp != nil {
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(shutdownCtx); err != nil {
				log.Warnf("OTLP traces provider shutdown: %v", err)
			}
		}()
	}
}

// setupOOMProf starts the OOM profiler pointed at rep. Both backends support
// memory profiles, so this is shared.
func setupOOMProf(cfg Config, rep oomprof.Reporter) (*oomprof.State, error) {
	// Process scanning is disabled: PIDs are fed from ReportTraceEvent.
	state, err := oomprof.SetupWithReporter(context.TODO(), &oomprof.Config{
		ScanInterval: 0,
		LogTracePipe: false,
		Verbose:      false,
		Symbolize:    false,
		ReportAlloc:  cfg.EnableOOMProfAllocs,
	}, rep)
	if err != nil {
		return nil, fmt.Errorf("failed to setup oomprof: %w", err)
	}
	log.Infof("OOM Profiler enabled, will report OOM traces to Parca")
	return state, nil
}
