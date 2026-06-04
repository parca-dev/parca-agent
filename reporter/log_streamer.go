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
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc"
)

// logProviderOptions is the resource-attribute payload attached to every batch
// shipped by the OTLP log exporter.
type logProviderOptions struct {
	ServiceName    string // service.name = "parca-agent"
	ServiceVersion string // service.version = build VCS revision
	HostName       string // host.name = agent --node
}

// Batching policy. The defaults the OTel SDK ships with are tuned for general
// telemetry workloads (1 s flush interval); for probe-fire-style events we
// want a tighter age cap so a single slow callback shows up in the UI within
// a few hundred ms of the dtor firing.
const (
	logExportMaxBatchSize = 512
	logExportInterval     = 250 * time.Millisecond
	logMaxQueueSize       = 4096
)

// newLogProvider constructs an OTel logs LoggerProvider that ships records as
// OTLP/gRPC ExportLogsServiceRequest messages over the supplied connection.
// The connection is shared with the profile-data path (caller owns it; we
// only borrow); the SDK's BatchProcessor runs its own goroutines for batching
// + retry and is torn down by the returned provider's Shutdown.
func newLogProvider(ctx context.Context, conn *grpc.ClientConn, opts logProviderOptions) (*sdklog.LoggerProvider, error) {
	exp, err := otlploggrpc.New(ctx, otlploggrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("create otlploggrpc exporter: %w", err)
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

	bp := sdklog.NewBatchProcessor(exp,
		sdklog.WithMaxQueueSize(logMaxQueueSize),
		sdklog.WithExportMaxBatchSize(logExportMaxBatchSize),
		sdklog.WithExportInterval(logExportInterval),
	)

	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(bp),
	), nil
}
