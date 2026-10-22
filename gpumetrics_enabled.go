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

//go:build gpumetrics

package main

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/internal/log"

	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/gpumetrics/nvidia"
	"github.com/parca-dev/parca-agent/metricexport"
	"github.com/parca-dev/parca-agent/reporter/metadata"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// startGPUMetrics collects NVML metrics from the node's NVIDIA GPUs and
// exports them over grpcConn until ctx is cancelled. Per-process metrics get
// their resource from a fork of the profiles' label resolver, so they carry
// the same identity as the process's profiles.
//
// This build links go-nvml, which dlopens libnvidia-ml at runtime: the binary
// must be dynamically linked and lazily bound (see build-gpu in the Makefile).
func startGPUMetrics(ctx context.Context, f flags.Flags, grpcConn *grpc.ClientConn, labels *processlabels.Resolver) {
	// Check the driver before NVML so nodes without GPUs never dlopen it.
	if gpumetrics.CountNVIDIAGPUs("/proc") == 0 {
		return
	}
	collector, err := nvidia.NewCollector()
	if err != nil {
		log.Warnf("GPU metrics unavailable: %v", err)
		return
	}
	if collector.DeviceCount() == 0 {
		log.Warn("GPU metrics unavailable: NVML reports no devices")
		return
	}
	resolver, err := labels.Fork()
	if err != nil {
		log.Warnf("GPU metrics not started: %v", err)
		return
	}
	producer := gpumetrics.NewProducer(collector)
	producer.SetProcessResourcer(gpumetrics.NewProcessResourcer(ctx, resolver, f.Node, metadata.InKubernetes()))

	hostAttrs := pcommon.NewMap()
	processlabels.PutHostAttributes(hostAttrs, f.Node, metadata.InKubernetes())
	exporter := metricexport.NewExporter(grpcConn, f.GpuMetrics.ExportInterval, hostAttrs.AsRaw())
	exporter.AddProducer(metricexport.ProducerConfig{
		Producer:  producer,
		ScopeName: gpumetrics.ScopeName,
	})

	log.Infof("GPU metrics enabled: collecting from %d NVIDIA device(s)", collector.DeviceCount())
	go func() {
		if err := exporter.Run(ctx); err != nil {
			log.Errorf("GPU metrics exporter stopped: %v", err)
		}
	}()
}
