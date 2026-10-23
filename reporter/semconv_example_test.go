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

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/config"
)

// fakeMetadataProvider lets relabel policies be exercised without a cluster.
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
		// OTLP providers emit these directly, alongside discovery labels when
		// relabel rules are configured. The example must leave them intact.
		"k8s.namespace.name":                                    "prod",
		"container.image.name":                                  "registry.example.com:5000/checkout",
		"container.image.tags":                                  "v1.4.2",
		"__meta_kubernetes_namespace":                           "prod",
		"__meta_kubernetes_pod_name":                            "checkout-7d9f8b6c5-xq2mn",
		"__meta_kubernetes_pod_container_image":                 "registry.example.com:5000/checkout:v1.4.2@sha256:abcdef",
		"__meta_kubernetes_pod_controller_name":                 "checkout",
		"__meta_kubernetes_pod_label_app_kubernetes_io_name":    "checkout-api",
		"__meta_kubernetes_pod_label_app_kubernetes_io_version": "1.4.2",
		"__meta_process_cmdline":                                "java -jar /app/checkout.jar",
	}
}

// exampleLabeler builds a labeler driven by the shipped example config and a
// fixed set of discovery labels.
func exampleLabeler(t *testing.T, meta map[string]string) *processLabeler {
	t.Helper()

	cfg, err := config.LoadFile("../config/examples/otlp-semconv-k8s.yaml")
	require.NoError(t, err, "the shipped example must parse and validate")
	require.NotEmpty(t, cfg.RelabelConfigs)

	return &processLabeler{
		resolver: newTestResolver(t, "node-7", cfg.RelabelConfigs, fakeMetadataProvider{labels: meta}),
	}
}

// TestSemconvExampleConfig checks the optional policies in the shipped config
// and that they preserve attributes the providers already produced.
func TestSemconvExampleConfig(t *testing.T) {
	l := exampleLabeler(t, podMetadata())

	res := l.labelsForTID(libpf.PID(1234), libpf.PID(1000),
		libpf.NewCommFromString("java"), 3, testProfileTypeSampling, nil)
	require.True(t, res.keep)

	for name, want := range map[string]string{
		"service.name":         "checkout-api",
		"service.version":      "1.4.2",
		"service.namespace":    "prod",
		"k8s.namespace.name":   "prod",
		"container.image.name": "registry.example.com:5000/checkout",
		"container.image.tags": "v1.4.2",

		"process.command_line": "java -jar /app/checkout.jar",
	} {
		require.Equal(t, want, res.resource.Get(name), "resource label %s", name)
	}

	// Discovery labels must not survive the relabel pass.
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
		{name: "app label wins", want: "checkout-api"},
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
				libpf.NewCommFromString("java"), 3, testProfileTypeSampling, nil)
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
		libpf.NewCommFromString("java"), 3, testProfileTypeSampling, nil)

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

	require.Equal(t, "checkout-api", attrs[attrServiceName],
		"the relabelled service.name must win over the comm-derived default")
	require.Equal(t, "prod", attrs["k8s.namespace.name"])

	// process.pid stays typed. The example warns against targeting it for
	// exactly this reason: a relabel rule would replace the int with a string.
	require.EqualValues(t, 1000, attrs[attrProcessPID])
	require.IsType(t, int64(0), attrs[attrProcessPID])
}
