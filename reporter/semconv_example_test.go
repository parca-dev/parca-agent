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
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/parca-dev/parca-agent/config"
	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// fakeMetadataProvider stands in for the container, process and system
// providers so the example config can be exercised without a cluster. The
// labels are the ones those providers really set; see containermetadata.go's
// addPodContainerMetadata and addObjectMetaLabels.
type fakeMetadataProvider struct {
	labels map[string]string
}

func (p fakeMetadataProvider) AddMetadata(_ context.Context, _ libpf.PID, lb *labels.Builder) bool {
	for k, v := range p.labels {
		lb.Set(k, v)
	}
	return true
}

func podMetadata() map[string]string {
	return map[string]string{
		"__meta_kubernetes_namespace":                                "prod",
		"__meta_kubernetes_pod_name":                                 "checkout-7d9f8b6c5-xq2mn",
		"__meta_kubernetes_pod_uid":                                  "9b2c1f34-5d6e-4a7b-8c9d-0e1f2a3b4c5d",
		"__meta_kubernetes_pod_container_name":                       "server",
		"__meta_kubernetes_pod_container_id":                         "a1b2c3d4e5f6",
		"__meta_kubernetes_pod_container_image":                      "registry.example.com/checkout:v1.4.2",
		"__meta_kubernetes_pod_node_name":                            "node-7",
		"__meta_kubernetes_pod_controller_kind":                      "Deployment",
		"__meta_kubernetes_pod_controller_name":                      "checkout",
		"__meta_kubernetes_pod_label_app_kubernetes_io_name":         "checkout",
		"__meta_kubernetes_pod_label_app_kubernetes_io_version":      "1.4.2",
		"__meta_process_executable_name":                             "java",
		"__meta_process_cmdline":                                     "java -jar /app/checkout.jar",
		"__meta_process_ppid":                                        "1",
		"__meta_kubernetes_node_label_topology_kubernetes_io_region": "us-east-1",
		"__meta_kubernetes_node_label_topology_kubernetes_io_zone":   "us-east-1b",
		"__meta_system_kernel_machine":                               "x86_64",
		"__meta_system_kernel_release":                               "6.8.0-40-generic",
	}
}

// exampleLabeler builds a labeler driven by the shipped example config and a
// fixed set of discovery labels.
func exampleLabeler(t *testing.T, meta map[string]string) *processLabeler {
	t.Helper()

	cfg, err := config.LoadFile("../config/examples/otlp-semconv-k8s.yaml")
	require.NoError(t, err, "the shipped example must parse and validate")
	require.NotEmpty(t, cfg.RelabelConfigs)

	lbls, err := lru.NewSynced[libpf.PID, labelRetrievalResult](1024, libpf.PID.Hash32)
	require.NoError(t, err)
	lbls.SetLifetime(time.Minute)

	return &processLabeler{
		labels:            lbls,
		nodeName:          "node-7",
		relabelConfigs:    cfg.RelabelConfigs,
		metadataProviders: []metadata.MetadataProvider{fakeMetadataProvider{labels: meta}},
	}
}

// TestSemconvExampleConfig is the test behind config/examples/otlp-semconv-k8s.yaml.
// The example is the answer to "which semconv attributes can parca-agent
// produce", so it is exercised rather than just documented: a provider that
// renames a discovery label breaks this, which is the point.
func TestSemconvExampleConfig(t *testing.T) {
	l := exampleLabeler(t, podMetadata())

	res := l.labelsForTID(libpf.PID(1234), libpf.PID(1000),
		libpf.NewCommFromString("java"), 3, support.TraceOriginSampling, nil)
	require.True(t, res.keep)

	for name, want := range map[string]string{
		"service.name":         "checkout",
		"service.version":      "1.4.2",
		"service.namespace":    "prod",
		"k8s.namespace.name":   "prod",
		"k8s.pod.name":         "checkout-7d9f8b6c5-xq2mn",
		"k8s.pod.uid":          "9b2c1f34-5d6e-4a7b-8c9d-0e1f2a3b4c5d",
		"k8s.container.name":   "server",
		"k8s.node.name":        "node-7",
		"k8s.deployment.name":  "checkout",
		"container.image.name": "registry.example.com/checkout",
		"container.image.tags": "v1.4.2",

		"process.executable.name": "java",
		"process.command_line":    "java -jar /app/checkout.jar",
		"process.parent_pid":      "1",

		"cloud.region":            "us-east-1",
		"cloud.availability_zone": "us-east-1b",

		"host.arch":  "amd64",
		"os.version": "6.8.0-40-generic",
	} {
		require.Equal(t, want, res.resource.Get(name), "resource label %s", name)
	}

	// The discovery labels themselves must not survive: promoting them is the
	// operator's decision, and the example promotes only the names above.
	res.resource.Range(func(l labels.Label) {
		require.NotContains(t, l.Name, "__meta_",
			"discovery labels are deleted after relabelling")
	})
}

// TestSemconvExampleServiceNameFallback pins the ordering the service.name
// rules depend on: each rule overwrites the previous one only when its own
// source label is set, so removing the strongest source falls back rather
// than emitting nothing.
func TestSemconvExampleServiceNameFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		without []string
		want    string
	}{
		{name: "app label wins", want: "checkout"},
		{
			name:    "falls back to the controller",
			without: []string{"__meta_kubernetes_pod_label_app_kubernetes_io_name"},
			want:    "checkout",
		},
		{
			name: "falls back to the pod",
			without: []string{
				"__meta_kubernetes_pod_label_app_kubernetes_io_name",
				"__meta_kubernetes_pod_controller_name",
			},
			want: "checkout-7d9f8b6c5-xq2mn",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := podMetadata()
			for _, k := range tc.without {
				delete(meta, k)
			}
			l := exampleLabeler(t, meta)
			res := l.labelsForTID(libpf.PID(1234), libpf.PID(1000),
				libpf.NewCommFromString("java"), 3, support.TraceOriginSampling, nil)
			require.Equal(t, tc.want, res.resource.Get("service.name"))
		})
	}
}

// TestSemconvExampleOverridesBuiltinServiceName is the reason the example can
// set service.name at all: resourceFor emits the built-in semconv attributes
// first and the label set verbatim afterwards, so a relabelled service.name
// overwrites the comm-derived default. Without this, every JVM pod in a
// cluster would report service.name="java".
func TestSemconvExampleOverridesBuiltinServiceName(t *testing.T) {
	l := exampleLabeler(t, podMetadata())
	res := l.labelsForTID(libpf.PID(1234), libpf.PID(1000),
		libpf.NewCommFromString("java"), 3, support.TraceOriginSampling, nil)

	b := testBuilder(t)
	b.AddSample(resourceLabels{
		Labels: res.resource,
		PID:    1000,
		// What serviceNameFor derives with no APM name: the thread comm.
		ServiceName: "java",
	}, cpuSampleType(19), sampleData{
		Frames:       frame(t, libpf.Frame{Type: libpf.NativeFrame}),
		Value:        1,
		SampleLabels: res.sample,
	})
	out := b.Build(time.Unix(0, 0), time.Unix(5, 0))
	attrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()

	require.Equal(t, "checkout", attrs[attrServiceName],
		"the relabelled service.name must win over the comm-derived default")
	require.Equal(t, "prod", attrs["k8s.namespace.name"])

	// process.pid stays typed. The example warns against targeting it for
	// exactly this reason: a relabel rule would replace the int with a string.
	require.EqualValues(t, 1000, attrs[attrProcessPID])
	require.IsType(t, int64(0), attrs[attrProcessPID])
}
