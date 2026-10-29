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

// TestNewProvidersLogsNeedOptIn pins that a remote-store connection alone,
// which every non-offline run has, does not turn on log export.
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

func TestSelfTraceExternalLabels(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	_, tp, err := newProviders(Config{
		TraceExporter: exp, AgentRevision: "rev1", NodeName: "node1",
		ExternalLabels: []Label{
			{Name: "parca.agent", Value: "true"},
			{Name: "service.name", Value: "other-service"},
			{Name: "host.name", Value: "other-host"},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })
	_, span := tp.Tracer("test").Start(t.Context(), "self")
	span.End()
	require.NoError(t, tp.ForceFlush(t.Context()))
	spans := exp.GetSpans()
	require.Len(t, spans, 1)
	attrs := map[string]any{}
	for _, kv := range spans[0].Resource.Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsInterface()
	}
	require.Equal(t, map[string]any{
		"parca.agent": "true", "service.name": "parca-agent", "host.name": "node1", "service.version": "rev1",
	}, attrs)
}
