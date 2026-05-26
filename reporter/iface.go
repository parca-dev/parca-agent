// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Apache License 2.0.
// See the file "LICENSE" for details.

package reporter

import (
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// ParcaReporter is the parca-agent reporter API: it accepts both profile
// trace events (via the embedded TraceReporter) and OTLP log events. Consumers
// that only need to publish logs (e.g. the probes BPF service, or any other
// non-uprobe producer) should depend on this interface rather than the
// concrete implementation, so they remain independent of profile-side code.
type ParcaReporter interface {
	reporter.TraceReporter

	// ReportLogEvents enqueues a batch of LogEvents for the Arrow log
	// streamer to ship. Returns nil on success. Drops on a saturated queue
	// are accounted for via the implementation's queue-drop counter and do
	// not return an error — callers are not expected to retry.
	ReportLogEvents(events []LogEvent) error
}
