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

package gpumetrics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/config"
	"github.com/parca-dev/parca-agent/reporter/metadata"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

type fakeProvider map[string]string

func (p fakeProvider) AddMetadata(_ context.Context, _ libpf.PID, lb *labels.Builder) bool {
	for k, v := range p {
		lb.Set(k, v)
	}
	return true
}

func newResolver(t *testing.T, relabelConfigs []*relabel.Config, meta map[string]string) *processlabels.Resolver {
	t.Helper()
	r, err := processlabels.New(processlabels.Config{
		CacheSize:      16,
		LabelTTL:       time.Minute,
		NodeName:       "gpu-node",
		RelabelConfigs: relabelConfigs,
		Providers:      []metadata.MetadataProvider{fakeProvider(meta)},
	})
	require.NoError(t, err)
	return r
}

func testGPU() GPU {
	return GPU{Index: 0, UUID: "GPU-1234", Model: "NVIDIA GB10", DriverVersion: "580.178.04"}
}

// dropPID drops one process, as a relabel rule would, and gives the rest only
// process.pid.
type dropPID uint32

func (d dropPID) PutResource(pid uint32, attrs pcommon.Map) bool {
	if pid == uint32(d) {
		return false
	}
	attrs.PutInt(processlabels.AttrProcessPID, int64(pid))
	return true
}

func TestProduceLayout(t *testing.T) {
	d := testGPU()
	p := NewProducer(nil)
	p.SetProcessResourcer(dropPID(222))

	p.RecordHost(func(b *MetricBuffer) {
		dp := b.Points(MetricGPUUtilization).AppendEmpty()
		d.PutAttrs(dp.Attributes())
		dp.SetDoubleValue(0.5)
		dp = b.Points(MetricGPUMemoryUsage).AppendEmpty()
		d.PutAttrs(dp.Attributes())
		dp.SetIntValue(1 << 30)
	})
	for _, pid := range []uint32{333, 111, 222} {
		p.RecordProcess(pid, func(b *MetricBuffer) {
			dp := b.Points(MetricProcessUtilization).AppendEmpty()
			d.PutIDAttrs(dp.Attributes())
			dp.SetDoubleValue(0.25)
		})
	}

	host := pmetric.NewMetricSlice()
	resources := pmetric.NewResourceMetricsSlice()
	require.NoError(t, p.Produce(host, resources))

	require.Equal(t, 2, host.Len())
	mem := host.At(0)
	util := host.At(1)
	require.Equal(t, MetricGPUMemoryUsage, mem.Name(), "metrics are in name order")
	require.Equal(t, MetricGPUUtilization, util.Name(), "metrics are in name order")
	require.Equal(t, "1", util.Unit())
	require.Equal(t, pmetric.MetricTypeGauge, util.Type())
	require.Equal(t, map[string]any{
		"hw.id":             "GPU-1234",
		"hw.name":           "nvidia0",
		"hw.type":           "gpu",
		"hw.vendor":         "NVIDIA",
		"hw.model":          "NVIDIA GB10",
		"hw.driver_version": "580.178.04",
	}, util.Gauge().DataPoints().At(0).Attributes().AsRaw())

	require.Equal(t, "By", mem.Unit())
	require.Equal(t, pmetric.MetricTypeSum, mem.Type(), "semconv makes memory usage an UpDownCounter")
	require.False(t, mem.Sum().IsMonotonic())
	require.Equal(t, pmetric.AggregationTemporalityCumulative, mem.Sum().AggregationTemporality())

	require.Equal(t, 2, resources.Len(), "the dropped process gets no resource")
	for i, wantPID := range []int64{111, 333} {
		rm := resources.At(i)
		require.Equal(t, processlabels.SchemaURL, rm.SchemaUrl())
		require.Equal(t, map[string]any{"process.pid": wantPID}, rm.Resource().Attributes().AsRaw())
		sm := rm.ScopeMetrics().At(0)
		require.Equal(t, ScopeName, sm.Scope().Name())
		m := sm.Metrics().At(0)
		require.Equal(t, MetricProcessUtilization, m.Name())
		require.Equal(t, map[string]any{"hw.id": "GPU-1234", "hw.name": "nvidia0"},
			m.Gauge().DataPoints().At(0).Attributes().AsRaw())
	}

	// Produce drains: the next call starts empty.
	host, resources = pmetric.NewMetricSlice(), pmetric.NewResourceMetricsSlice()
	require.NoError(t, p.Produce(host, resources))
	require.Zero(t, host.Len())
	require.Zero(t, resources.Len())
}

// TestProcessResourceMatchesProfiles runs the semconv example config through
// the GPU process resource, so a process's GPU metrics carry the same k8s and
// service identity its profiles do (see reporter/semconv_example_test.go).
func TestProcessResourceMatchesProfiles(t *testing.T) {
	cfg, err := config.LoadFile("../config/examples/otlp-semconv-k8s.yaml")
	require.NoError(t, err)

	resolver := newResolver(t, cfg.RelabelConfigs, map[string]string{
		"comm":                                               "python3",
		"__meta_kubernetes_namespace":                        "ml",
		"__meta_kubernetes_pod_name":                         "trainer-0",
		"__meta_kubernetes_pod_container_name":               "trainer",
		"__meta_kubernetes_pod_label_app_kubernetes_io_name": "trainer",
	})
	r := NewProcessResourcer(context.Background(), resolver, "gpu-node", true).(*processResourcer)
	r.procRoot = t.TempDir() // no /proc/<pid>/exe: the path is best effort

	attrs := pcommon.NewMap()
	require.True(t, r.PutResource(4242, attrs))
	got := attrs.AsRaw()

	for k, want := range map[string]any{
		"process.pid":             int64(4242),
		"process.executable.name": "python3",
		"host.name":               "gpu-node",
		"k8s.node.name":           "gpu-node",
		"k8s.namespace.name":      "ml",
		"k8s.pod.name":            "trainer-0",
		"k8s.container.name":      "trainer",
		"service.name":            "trainer",
	} {
		require.Equal(t, want, got[k], k)
	}
	require.NotContains(t, got, "comm", "comm is renamed to process.executable.name")
	require.NotContains(t, got, "node", "host.name carries the node name")
}

// TestProcessResourceFromEnv checks a process can name itself with the OTel
// environment variables, as it can for its profiles, and can add attributes
// but not override the ones the agent derives.
func TestProcessResourceFromEnv(t *testing.T) {
	resolver := newResolver(t, nil, map[string]string{"comm": "python3"})
	r := NewProcessResourcer(context.Background(), resolver, "gpu-node", false).(*processResourcer)
	r.procRoot = t.TempDir()
	procDir := filepath.Join(r.procRoot, "4242")
	require.NoError(t, os.Mkdir(procDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "environ"), []byte(
		"PATH=/usr/bin\x00OTEL_SERVICE_NAME=trtllm\x00"+
			"OTEL_RESOURCE_ATTRIBUTES=service.namespace=dgx-demo,host.name=elsewhere\x00"), 0o644))

	attrs := pcommon.NewMap()
	require.True(t, r.PutResource(4242, attrs))
	got := attrs.AsRaw()
	require.Equal(t, "trtllm", got["service.name"])
	require.Equal(t, "dgx-demo", got["service.namespace"])
	require.Equal(t, "gpu-node", got["host.name"], "the agent's host.name wins")
	require.NotContains(t, got, "PATH")
}

func TestProcessResourceRelabelDrop(t *testing.T) {
	drop := &relabel.Config{Action: relabel.Drop, SourceLabels: []model.LabelName{"comm"}, Regex: relabel.MustNewRegexp("python3"), Separator: ";"}
	resolver := newResolver(t, []*relabel.Config{drop}, map[string]string{"comm": "python3"})
	r := NewProcessResourcer(context.Background(), resolver, "gpu-node", false)
	require.False(t, r.PutResource(4242, pcommon.NewMap()))
}
