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
	"github.com/parca-dev/oomprof/oomprof"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/otel/log"
)

// ParcaReporter is the parca-agent superset of the otel ebpf-profiler
// reporter interfaces. It carries everything `main.go` needs to drive the
// agent end-to-end:
//
//   - reporter.Reporter           (ReportTraceEvent + Start + Stop)
//   - reporter.ExecutableReporter (ReportExecutable)
//   - ReportMetrics               (for the otel-side metrics fan-in)
//   - ReportMemoryTraces          (the dedicated path for oomprof and any
//     future memory-attributed-trace producer)
//   - Logger                      (OTel logs for in-process producers)
//
// `ReportMemoryTraces` exists so memory profiles don't have to ride on the
// TraceReporter contract. Callers pass a per-process batch of
// stacktrace+counter samples and the implementation writes the
// inuse/alloc rows directly. The signature mirrors the upstream
// oomprof.Reporter contract because oomprof is the only producer today;
// if a non-oomprof producer ever appears we can extract a parca-agent-
// local type then.
type ParcaReporter interface {
	reporter.Reporter
	reporter.ExecutableReporter

	// ReportMetrics fans otel-side metric updates back into the agent's
	// prometheus registry.
	ReportMetrics(timestamp uint32, ids []uint32, values []int64)

	// ReportMemoryTraces emits one or more memory-attributed traces for a
	// single process snapshot. The samples slice carries the stacks plus
	// alloc/free counters; meta carries the per-process attribution
	// (PID, comm, executable path, build ID). Implementations should
	// hold their writer lock at most once per call.
	ReportMemoryTraces(samples []oomprof.Sample, meta oomprof.SampleMeta) error

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
