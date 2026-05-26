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
)

// ParcaReporter is the parca-agent reporter API: it accepts profile trace
// events (via the embedded TraceReporter) and hands out OTel logs Loggers for
// any in-process producer that wants to ship records via the agent's shared
// OTLP/gRPC connection.
//
// Consumers that only need to publish logs (e.g. the probes BPF service, or
// the logrus -> OTLP hook) should depend on this interface rather than the
// concrete implementation, so they remain independent of profile-side code.
type ParcaReporter interface {
	reporter.TraceReporter

	// Logger returns an OTel logs Logger bound to the given instrumentation
	// scope name. Callers should use distinct scope names per producer (e.g.
	// "parca-agent.agent" for the logrus hook, "parca-agent.probes" for the
	// BPF probe service); the OTLP server surfaces the scope as
	// attributes_scope.name so consumers can filter by producer.
	//
	// When the reporter was constructed without a gRPC conn (offline mode),
	// the returned Logger is a no-op.
	Logger(scope string) log.Logger
}
