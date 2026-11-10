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
	"go.opentelemetry.io/otel/attribute"
)

func TestPutProcessAttributesPreservesResolvedTypes(t *testing.T) {
	attrs := pcommon.NewMap()
	PutProcessAttributes(attrs, Process{ResourceAttrs: attribute.NewSet(
		attribute.String("service.name", "accountant"),
		attribute.String("blank", ""), attribute.Bool("enabled", false),
		attribute.Int64("port", 8080), attribute.Float64("ratio", 0.25),
		attribute.BoolSlice("flags", []bool{false, true}),
		attribute.Int64Slice("ports", []int64{8080, 443}),
		attribute.Float64Slice("ratios", []float64{0.25, 0.75}),
		attribute.StringSlice("zones", []string{"west", "east"}),
		attribute.KeyValue{Key: "bytes", Value: attribute.ByteSliceValue([]byte{0, 255})},
		attribute.KeyValue{Key: "nested", Value: attribute.MapValue(attribute.KeyValue{
			Key: "values", Value: attribute.SliceValue(attribute.Int64Value(7), attribute.StringValue("two"), attribute.Value{}),
		})},
		attribute.KeyValue{Key: "unset"},
	)}, "", false)
	require.Equal(t, map[string]any{
		"service.name": "accountant", "blank": "", "enabled": false,
		"port": int64(8080), "ratio": 0.25,
		"flags": []any{false, true}, "ports": []any{int64(8080), int64(443)},
		"ratios": []any{0.25, 0.75}, "zones": []any{"west", "east"},
		"bytes": []byte{0, 255}, "nested": map[string]any{"values": []any{int64(7), "two", nil}}, "unset": nil,
	}, attrs.AsRaw())
}

// TestPutProcessAttributesIdentityWins checks the process's own attributes
// never override what the agent or a relabel rule set.
func TestPutProcessAttributesIdentityWins(t *testing.T) {
	attrs := pcommon.NewMap()
	PutProcessAttributes(attrs, Process{
		Labels:         labels.FromStrings("team", "relabeled", "comm", "worker-title", "container.image.tags", "v1,v2", "container.image.repo_digests", "team/app@sha256:abcdef"),
		PID:            42,
		ExecutablePath: "/usr/bin/python3.13",
		ContainerID:    "real-container",
		ResourceAttrs: attribute.NewSet(
			attribute.String("service.name", "trtllm"),
			attribute.String("service.namespace", "dgx-demo"),
			attribute.String("host.name", "elsewhere"),
			attribute.Int64("process.pid", 1),
			attribute.String("process.executable.name", "wrong"),
			attribute.String("container.id", "wrong"),
			attribute.String("team", "from-context")),
	}, "gpu-node", false)

	got := attrs.AsRaw()
	require.Equal(t, "dgx-demo", got["service.namespace"])
	require.Equal(t, "gpu-node", got["host.name"])
	require.Equal(t, int64(42), got["process.pid"])
	require.Equal(t, "relabeled", got["team"])
	require.Equal(t, "trtllm", got["service.name"])
	require.Equal(t, "python3.13", got["process.executable.name"])
	require.Equal(t, "real-container", got["container.id"])
	require.NotContains(t, got, "comm")
	require.Equal(t, []any{"v1", "v2"}, got["container.image.tags"])
	require.Equal(t, []any{"team/app@sha256:abcdef"}, got["container.image.repo_digests"])
}
