// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// noopLogExporter stands in for the gRPC log exporter. Its presence is what the
// test varies, so it needs to do nothing beyond satisfying the interface.
type noopLogExporter struct{}

func (noopLogExporter) Export(context.Context, []sdklog.Record) error { return nil }
func (noopLogExporter) Shutdown(context.Context) error                { return nil }
func (noopLogExporter) ForceFlush(context.Context) error              { return nil }

// TestNewProvidersLogsNeedOptIn pins the thing that made the LoggerProvider a
// silent allocator: it used to be built whenever a remote-store connection
// existed, which is true for every non-offline run, so the batch processor
// churned records in configurations that never attached anything to Logger().
func TestNewProvidersLogsNeedOptIn(t *testing.T) {
	t.Run("exporter present but not opted in", func(t *testing.T) {
		lp, _, err := newProviders(Config{LogExporter: noopLogExporter{}})
		require.NoError(t, err)
		require.Nil(t, lp, "a log exporter alone must not build a LoggerProvider")
	})

	// The positive control. Without it the case above is vacuous: an
	// implementation that never built a provider would satisfy it too.
	t.Run("opted in", func(t *testing.T) {
		lp, _, err := newProviders(Config{
			LogExporter:    noopLogExporter{},
			ExportSelfLogs: true,
		})
		require.NoError(t, err)
		require.NotNil(t, lp, "ExportSelfLogs must build a LoggerProvider")
	})
}

// TestNewProvidersTracesUnaffected guards the blast radius: the logs gate must
// not have been applied to traces, whose provider the probe service needs.
func TestNewProvidersTracesUnaffected(t *testing.T) {
	_, tp, err := newProviders(Config{TraceExporter: tracetest.NewNoopExporter()})
	require.NoError(t, err)
	require.NotNil(t, tp, "a trace exporter must still build a TracerProvider")
}
