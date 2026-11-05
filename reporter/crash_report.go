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
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"google.golang.org/grpc"
)

// crashReportTimeout bounds how long the supervising parent waits to deliver
// a crash report before it exits.
const crashReportTimeout = 10 * time.Second

// CrashReport describes an abnormal exit of the supervised agent process.
type CrashReport struct {
	// Stderr is the tail of the child's stderr. A Go panic or fatal error is
	// printed there by the runtime, not through the logger, so the agent's
	// own OTLP log stream never contains it.
	Stderr string
	// Status is the child's exit status as reported by os/exec, for example
	// "exit status 2" or "signal: killed".
	Status   string
	ExitCode int
	PID      int

	ServiceVersion string
	HostName       string
	HostArch       string
	KernelRelease  string
	ExternalLabels map[string]string
}

// SendCrashReport exports one FATAL log record for an abnormal exit of the
// supervised agent over conn. It is the OTLP counterpart of the Parca
// TelemetryService.ReportPanic call, for remote stores that speak OTLP.
func SendCrashReport(ctx context.Context, conn *grpc.ClientConn, r CrashReport) error {
	ctx, cancel := context.WithTimeout(ctx, crashReportTimeout)
	defer cancel()

	exp, err := newGRPCLogExporter(ctx, conn)
	if err != nil {
		return err
	}
	lp := newLogProvider(exp, logProviderOptions{
		ServiceName:    "parca-agent",
		ServiceVersion: r.ServiceVersion,
		HostName:       r.HostName,
		ExternalLabels: r.ExternalLabels,
	})

	var rec otellog.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(otellog.SeverityFatal)
	rec.SetSeverityText("FATAL")
	rec.SetEventName("parca_agent.crash")
	rec.SetBody(attribute.StringValue(fmt.Sprintf("parca-agent exited abnormally (%s)\n\n%s", r.Status, r.Stderr)))
	rec.AddAttributes(
		attribute.Int("process.exit.code", r.ExitCode),
		attribute.Int("process.pid", r.PID),
		attribute.String("host.arch", r.HostArch),
		attribute.String("os.version", r.KernelRelease),
	)
	lp.Logger("parca-agent.supervisor").Emit(ctx, rec)

	// Shutdown flushes the batch processor and reports the export error.
	return errors.Join(lp.ForceFlush(ctx), lp.Shutdown(ctx))
}
