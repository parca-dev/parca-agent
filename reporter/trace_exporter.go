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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
)

// tracerProviderOptions is the resource-attribute payload attached to every
// batch shipped by the OTLP trace exporter. Same shape as the log-side
// equivalent so both pipelines stamp identical resource attrs onto records.
type tracerProviderOptions struct {
	ServiceName    string // service.name = "parca-agent"
	ServiceVersion string // service.version = build VCS revision
	HostName       string // host.name = agent --node
}

// Batching policy. Same tuning as the log pipeline: tighter than the SDK's
// 5 s default so a slow callback span shows up in the UI a few hundred ms
// after the dtor fires.
const (
	traceExportMaxBatchSize = 512
	traceExportInterval     = 250 * time.Millisecond
	traceMaxQueueSize       = 4096
)

// newTracerProvider constructs an OTel TracerProvider that ships spans as
// OTLP/gRPC ExportTraceServiceRequest messages over the supplied connection.
// The connection is shared with the profile-data path (caller owns it; we
// only borrow); the SDK's BatchSpanProcessor runs its own goroutines for
// batching + retry and is torn down by the returned provider's Shutdown.
//
// All spans are sampled (AlwaysSample). Producers that need to drop volume
// -- e.g. the probes BPF service -- already filter in-kernel before a record
// ever crosses into user space, so adding a head sampler here would just
// shadow that filter.
func newTracerProvider(ctx context.Context, conn *grpc.ClientConn, opts tracerProviderOptions) (*sdktrace.TracerProvider, error) {
	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("create otlptracegrpc exporter: %w", err)
	}

	attrs := []attribute.KeyValue{
		attribute.String("service.name", opts.ServiceName),
	}
	if opts.ServiceVersion != "" {
		attrs = append(attrs, attribute.String("service.version", opts.ServiceVersion))
	}
	if opts.HostName != "" {
		attrs = append(attrs, attribute.String("host.name", opts.HostName))
	}
	res := resource.NewSchemaless(attrs...)

	bsp := sdktrace.NewBatchSpanProcessor(exp,
		sdktrace.WithMaxQueueSize(traceMaxQueueSize),
		sdktrace.WithMaxExportBatchSize(traceExportMaxBatchSize),
		sdktrace.WithBatchTimeout(traceExportInterval),
	)

	return sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	), nil
}
