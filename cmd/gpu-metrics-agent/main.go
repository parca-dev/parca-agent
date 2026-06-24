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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/gpumetrics/supervisor"
	"github.com/parca-dev/parca-agent/metricexport"
)

type cliFlags struct {
	Log            flags.FlagsLogs        `embed:"" prefix:"log-"`
	Node           string                 `default:"${hostname}" help:"The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name."`
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

	producer, err := gpumetrics.NewProducer()
	if err != nil {
		log.Warnf("GPU metrics unavailable: %v", err)
		return supervisor.ExitCodeUnavailable
	}
	if producer.DeviceCount() == 0 {
		log.Warn("GPU metrics unavailable: NVML reports no devices")
		return supervisor.ExitCodeUnavailable
	}
	producer.SetLabelResolver(newLabelResolver(ctx, f.Node))

	grpcConn, err := f.RemoteStore.WaitGrpcEndpoint(ctx, prometheus.NewRegistry(), noop.NewTracerProvider())
	if err != nil {
		log.Errorf("failed to connect to remote store: %v", err)
		return 1
	}
	defer grpcConn.Close()

	log.Infof("GPU metrics enabled: collecting from %d NVIDIA device(s)", producer.DeviceCount())
	exporter := metricexport.NewExporter(grpcConn, f.ExportInterval, map[string]any{"node": f.Node})
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

// newLabelResolver builds a container/pod label resolver for per-process GPU
// metrics. On failure it logs and returns a nil resolver, so per-process
// metrics fall back to pid/comm only rather than disabling GPU metrics
// entirely. The return type is the interface, so a nil here is a true nil
// interface.
func newLabelResolver(ctx context.Context, nodeName string) gpumetrics.LabelResolver {
	resolver, err := gpumetrics.NewContainerLabelResolver(ctx, nodeName)
	if err != nil {
		log.Warnf("GPU metrics: container label enrichment disabled: %v", err)
		return nil
	}
	return resolver
}
