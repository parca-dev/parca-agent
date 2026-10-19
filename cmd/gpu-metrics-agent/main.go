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

// gpu-metrics-agent collects NVIDIA GPU metrics via NVML and exports them over
// OTLP to a Parca-compatible remote store.
//
// It is a separate binary from parca-agent because go-nvml dlopens
// libnvidia-ml at runtime, which requires cgo and a dynamically linked
// executable; parca-agent itself stays fully static. parca-agent launches this
// binary as a subprocess (see gpumetrics/supervisor) when the node has NVIDIA
// GPUs, forwarding its remote-store settings, but it can also be run on its
// own.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/relabel"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/parca-dev/parca-agent/config"
	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/gpumetrics/nvidia"
	"github.com/parca-dev/parca-agent/gpumetrics/supervisor"
	"github.com/parca-dev/parca-agent/metricexport"
	"github.com/parca-dev/parca-agent/reporter/metadata"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

type cliFlags struct {
	Log            flags.FlagsLogs        `embed:"" prefix:"log-"`
	Node           string                 `default:"${hostname}" help:"The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name."`
	ConfigPath     string                 `default:""            help:"Path to parca-agent's config file. Its relabel_configs shape the resource of per-process GPU metrics exactly as they shape profiles."`
	LabelTTL       time.Duration          `default:"10m"         help:"How long a process's resolved labels are cached."`
	ExportInterval time.Duration          `default:"10s"         help:"How frequently collected GPU metrics are batched and exported over OTLP."`
	RemoteStore    flags.FlagsRemoteStore `embed:"" prefix:"remote-store-"`
}

func main() {
	os.Exit(run())
}

func run() int {
	hostname, _ := os.Hostname()
	var f cliFlags
	kong.Parse(&f, kong.Vars{"hostname": hostname})
	f.Log.ConfigureLogger()

	if f.RemoteStore.Address == "" {
		log.Error("--remote-store-address is required")
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	collector, err := nvidia.NewCollector()
	if err != nil {
		log.Warnf("GPU metrics unavailable: %v", err)
		return supervisor.ExitCodeUnavailable
	}
	if collector.DeviceCount() == 0 {
		log.Warn("GPU metrics unavailable: NVML reports no devices")
		return supervisor.ExitCodeUnavailable
	}
	resolver, err := newProcessLabelResolver(ctx, f)
	if err != nil {
		log.Errorf("failed to set up process labels: %v", err)
		return 1
	}
	producer := gpumetrics.NewProducer(collector)
	producer.SetProcessResourcer(gpumetrics.NewProcessResourcer(ctx, resolver, f.Node, metadata.InKubernetes()))

	grpcConn, err := f.RemoteStore.WaitGrpcEndpoint(ctx, prometheus.NewRegistry(), noop.NewTracerProvider())
	if err != nil {
		log.Errorf("failed to connect to remote store: %v", err)
		return 1
	}
	defer grpcConn.Close()

	log.Infof("GPU metrics enabled: collecting from %d NVIDIA device(s)", collector.DeviceCount())
	hostAttrs := pcommon.NewMap()
	processlabels.PutHostAttributes(hostAttrs, f.Node, metadata.InKubernetes())
	exporter := metricexport.NewExporter(grpcConn, f.ExportInterval, hostAttrs.AsRaw())
	exporter.AddProducer(metricexport.ProducerConfig{
		Producer:  producer,
		ScopeName: gpumetrics.ScopeName,
	})
	if err := exporter.Run(ctx); err != nil {
		log.Errorf("GPU metrics exporter stopped: %v", err)
		return 1
	}
	return 0
}

// newProcessLabelResolver builds the label resolver parca-agent uses for
// profiles, driven by the same config file, so per-process GPU metrics carry
// the same identity as the process's profiles. There is no executable cache
// here, so relabel rules on __meta_process_executable_* see nothing.
func newProcessLabelResolver(ctx context.Context, f cliFlags) (*processlabels.Resolver, error) {
	var relabelConfigs []*relabel.Config
	if f.ConfigPath != "" {
		cfg, err := config.LoadFile(f.ConfigPath)
		switch {
		case errors.Is(err, config.ErrEmptyConfig):
		case err != nil:
			return nil, fmt.Errorf("read config: %w", err)
		default:
			relabelConfigs = cfg.RelabelConfigs
		}
	}
	providers, err := processlabels.DefaultProviders(ctx, f.Node, "", nil)
	if err != nil {
		return nil, err
	}
	return processlabels.New(processlabels.Config{
		CacheSize:      1024,
		LabelTTL:       f.LabelTTL,
		NodeName:       f.Node,
		RelabelConfigs: relabelConfigs,
		Providers:      providers,
	})
}
