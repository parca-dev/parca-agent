// SPDX-License-Identifier: Apache-2.0

package metricexport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

type metricsServer struct {
	pmetricotlp.UnimplementedGRPCServer
	received chan pmetric.Metrics
}

func (s *metricsServer) Export(_ context.Context, req pmetricotlp.ExportRequest) (pmetricotlp.ExportResponse, error) {
	m := pmetric.NewMetrics()
	req.Metrics().CopyTo(m)
	s.received <- m
	return pmetricotlp.NewExportResponse(), nil
}

type idleCollector struct{}

func (idleCollector) Collect(ctx context.Context, _ *gpumetrics.Producer) error {
	<-ctx.Done()
	return nil
}

func TestExternalLabelsPreserveHostAndProcessResources(t *testing.T) {
	// The agent's environment must not become the node-wide GPU resource.
	t.Setenv("OTEL_SERVICE_NAME", "profiler")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "k8s.pod.uid=profiler-pod,container.id=profiler-container")
	flags.RegisterProtoCodec()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	receiver := &metricsServer{received: make(chan pmetric.Metrics, 1)}
	pmetricotlp.RegisterGRPCServer(srv, receiver)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	external := map[string]string{"parca.agent": "true", "host.name": "other-host", "empty": ""}
	resolver, err := processlabels.New(processlabels.Config{CacheSize: 16})
	require.NoError(t, err)
	declared := func(libpf.PID) (processlabels.Declared, bool) {
		return processlabels.Declared{Env: map[libpf.String]libpf.String{
			libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("workload"),
			libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("k8s.pod.uid=workload-pod,container.id=workload-container"),
		}}, true
	}
	producer := gpumetrics.NewProducer(idleCollector{})
	producer.SetProcessResourcer(gpumetrics.NewProcessResourcer(t.Context(), resolver, declared, "gpu-node", true, external))
	producer.RecordHost(func(b *gpumetrics.MetricBuffer) {
		b.Points(gpumetrics.MetricGPUUtilization).AppendEmpty().SetDoubleValue(0.8)
	})
	producer.RecordProcess(4242, func(b *gpumetrics.MetricBuffer) {
		b.Points(gpumetrics.MetricProcessUtilization).AppendEmpty().SetDoubleValue(0.3)
	})
	exporter := NewExporter(conn, time.Millisecond, map[string]any{"host.name": "gpu-node", "k8s.node.name": "gpu-node"}, external)
	exporter.AddProducer(ProducerConfig{Producer: producer, ScopeName: gpumetrics.ScopeName})
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- exporter.Run(ctx) }()
	var m pmetric.Metrics
	select {
	case m = <-receiver.received:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OTLP metrics")
	}
	cancel()
	require.NoError(t, <-done)
	require.Equal(t, 2, m.ResourceMetrics().Len())
	require.Equal(t, map[string]any{
		"host.name": "gpu-node", "k8s.node.name": "gpu-node", "parca.agent": "true", "empty": "",
	}, m.ResourceMetrics().At(0).Resource().Attributes().AsRaw())
	process := m.ResourceMetrics().At(1).Resource().Attributes().AsRaw()
	require.Equal(t, "true", process["parca.agent"])
	require.Equal(t, "workload", process["service.name"])
	require.Equal(t, "workload-pod", process["k8s.pod.uid"])
	require.Equal(t, "workload-container", process["container.id"])
	require.Equal(t, "gpu-node", process["host.name"])
}
