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
