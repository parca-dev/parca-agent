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

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// defaultEnrichmentLabels is the curated set of container/pod labels attached to
// per-process GPU metrics. It is intentionally small: each label combination is
// a distinct time series, so we keep only stable, low-churn identifiers useful
// for grouping (namespace, pod, container) and deliberately exclude high-churn
// or verbose labels (pod_container_image, pod_ip, ...) that would inflate
// cardinality. These match labels parca-agent already attaches to profiles, so
// GPU metrics and profiles join on the same pod/container identity.
var defaultEnrichmentLabels = map[string]struct{}{
	"namespace":           {},
	"pod":                 {},
	"pod_container_name":  {},
	"pod_container_id":    {},
	"pod_uid":             {},
	"pod_controller_kind": {},
	"pod_controller_name": {},
}

// ContainerLabelResolver enriches per-process GPU metrics with Kubernetes
// container/pod labels, using parca-agent's container metadata provider. It
// implements LabelResolver.
type ContainerLabelResolver struct {
	ctx      context.Context
	provider metadata.MetadataProvider
	allow    map[string]struct{}
}

// NewContainerLabelResolver builds a resolver backed by the container metadata
// provider for the given Kubernetes node. The provider maintains its own caches,
// so per-PID lookups on the hot path are cheap after the first resolution.
func NewContainerLabelResolver(ctx context.Context, nodeName string) (*ContainerLabelResolver, error) {
	provider, err := metadata.NewContainerMetadataProvider(ctx, nodeName)
	if err != nil {
		return nil, err
	}
	return &ContainerLabelResolver{
		ctx:      ctx,
		provider: provider,
		allow:    defaultEnrichmentLabels,
	}, nil
}

// LabelsForPID returns the curated container/pod labels for a host PID. PIDs
// that don't belong to a container (or that can't be resolved) yield an empty
// map, leaving the data point with only its pid/comm attributes.
func (r *ContainerLabelResolver) LabelsForPID(pid uint32) map[string]string {
	lb := labels.NewBuilder(labels.EmptyLabels())
	r.provider.AddMetadata(r.ctx, libpf.PID(pid), lb)

	out := make(map[string]string, len(r.allow))
	lb.Range(func(l labels.Label) {
		if _, ok := r.allow[l.Name]; ok && l.Value != "" {
			out[l.Name] = l.Value
		}
	})
	return out
}
