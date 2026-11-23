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

package main

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/internal/log"
	"github.com/parca-dev/parca-agent/metricexport"
	"github.com/parca-dev/parca-agent/parcagpu"
	"github.com/parca-dev/parca-agent/reporter"
	"github.com/parca-dev/parca-agent/reporter/metadata"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// startKernelStats exports parcagpu's exact kernel execution counts and
// durations as OTLP metrics over grpcConn, on the GPU metrics export interval.
// Unlike NVML metrics it needs no driver library, so every build has it. It
// returns nil, which makes parcagpu drop the records, when there is no
// connection or GPU metrics are disabled.
func startKernelStats(ctx context.Context, f flags.Flags, grpcConn *grpc.ClientConn,
	rep reporter.ParcaReporter, resource gpumetrics.ResourceLookup,
) parcagpu.KernelStatsSink {
	if grpcConn == nil || f.GpuMetrics.Disable {
		return nil
	}
	resolver, err := rep.ProcessLabels().Fork()
	if err != nil {
		log.Warnf("CUDA kernel stats not started: %v", err)
		return nil
	}
	producer := parcagpu.NewKernelStatsProducer(gpumetrics.NewProcessResourcer(
		ctx, resolver, resource, f.Node, metadata.InKubernetes(), f.Metadata.ExternalLabels))

	hostAttrs := pcommon.NewMap()
	processlabels.PutHostAttributes(hostAttrs, f.Node, metadata.InKubernetes())
	exporter := metricexport.NewExporter(grpcConn, f.GpuMetrics.ExportInterval, hostAttrs.AsRaw(), f.Metadata.ExternalLabels)
	exporter.AddProducer(metricexport.ProducerConfig{
		Producer:  producer,
		ScopeName: parcagpu.KernelStatsScopeName,
	})
	go func() {
		if err := exporter.Run(ctx); err != nil {
			log.Errorf("CUDA kernel stats exporter stopped: %v", err)
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := producer.LostFirings(); n > 0 {
					log.Warnf("[cuda] missed %d kernel_stats firings in the last minute; kernel counts are low", n)
				}
			}
		}
	}()
	return producer
}
