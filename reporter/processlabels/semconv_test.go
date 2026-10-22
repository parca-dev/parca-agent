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

package processlabels

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func otelEnv(serviceName, resourceAttrs string) map[libpf.String]libpf.String {
	env := map[libpf.String]libpf.String{}
	if serviceName != "" {
		env[envServiceName] = libpf.Intern(serviceName)
	}
	if resourceAttrs != "" {
		env[envResourceAttributes] = libpf.Intern(resourceAttrs)
	}
	return env
}

func TestServiceNameFromEnv(t *testing.T) {
	comm := libpf.NewCommFromString("python3")
	for _, tc := range []struct {
		name, serviceName, resourceAttrs, want string
	}{
		{"none", "", "", "python3"},
		{"OTEL_SERVICE_NAME", "trtllm", "", "trtllm"},
		{"resource attributes", "", "service.namespace=dgx-demo,service.name=vllm", "vllm"},
		{"OTEL_SERVICE_NAME wins", "trtllm", "service.name=vllm", "trtllm"},
		{"percent-encoded", "", "service.name=my%20svc", "my svc"},
		{"bad encoding", "", "service.name=%zz", "python3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want,
				ServiceName("", comm, libpf.NullString, otelEnv(tc.serviceName, tc.resourceAttrs)))
		})
	}
}

func TestResourceAttributesFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name, resourceAttrs string
		want                []Attribute
	}{
		{"unset", "", nil},
		{"only service.name", "service.name=vllm", nil},
		{
			"in order, without service.name",
			" service.namespace = dgx-demo ,service.name=vllm,deployment.environment.name=demo",
			[]Attribute{{"service.namespace", "dgx-demo"}, {"deployment.environment.name", "demo"}},
		},
		{"metadata dropped", "service.namespace=dgx-demo;meta=1", []Attribute{{"service.namespace", "dgx-demo"}}},
		{"percent-encoded", "team=gpu%2Cinfra", []Attribute{{"team", "gpu,infra"}}},
		{"malformed entries skipped", "novalue,=x,empty=,bad=%zz,ok=1", []Attribute{{"ok", "1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ResourceAttributesFromEnv(otelEnv("", tc.resourceAttrs)))
		})
	}
}

// TestPutProcessAttributesEnvFillsOnly checks the process's own attributes
// never override what the agent or a relabel rule set.
func TestPutProcessAttributesEnvFillsOnly(t *testing.T) {
	attrs := pcommon.NewMap()
	PutProcessAttributes(attrs, Process{
		Labels:      labels.FromStrings("team", "relabeled"),
		PID:         42,
		ServiceName: "trtllm",
		EnvAttributes: []Attribute{
			{"service.namespace", "dgx-demo"},
			{"host.name", "elsewhere"},
			{"process.pid", "1"},
			{"team", "from-env"},
		},
	}, "gpu-node", false)

	got := attrs.AsRaw()
	require.Equal(t, "dgx-demo", got["service.namespace"])
	require.Equal(t, "gpu-node", got["host.name"])
	require.Equal(t, int64(42), got["process.pid"])
	require.Equal(t, "relabeled", got["team"])
	require.Equal(t, "trtllm", got["service.name"])
}
