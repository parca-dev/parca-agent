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
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// ParcaReporter is the parca-agent reporter API: it accepts profile trace
// events (via the embedded TraceReporter) and hands out OTel Loggers and
// Tracers for any in-process producer that wants to ship records via the
// agent's shared OTLP/gRPC connection.
//
// Consumers that only need to publish logs or traces (e.g. the logrus -> OTLP
// hook, or the probes BPF service) should depend on this interface rather
// than the concrete implementation, so they remain independent of
// profile-side code.
type ParcaReporter interface {
	reporter.TraceReporter

	// Logger returns an OTel logs Logger bound to the given instrumentation
	// scope name. The OTLP server surfaces the scope as attributes_scope.name
	// so consumers can filter by producer.
	//
	// When the reporter was constructed without a gRPC conn (offline mode),
	// the returned Logger is a no-op.
	Logger(scope string) log.Logger

	// Tracer returns an OTel Tracer bound to the given instrumentation scope
	// name. Used by producers that model interval-shaped events (probe fires,
	// etc.) as spans rather than logs; the OTLP server surfaces the scope as
	// the span's instrumentation-scope name so consumers can filter by
	// producer.
	//
	// When the reporter was constructed without a gRPC conn (offline mode),
	// the returned Tracer is a no-op.
	Tracer(scope string) trace.Tracer
}
