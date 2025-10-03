package metadata

import (
	"context"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type agentMetadataProvider struct {
	revision string
}

func NewAgentMetadataProvider(revision string) MetadataProvider {
	return &agentMetadataProvider{revision: revision}
}

func (p *agentMetadataProvider) AddMetadata(_ context.Context, _ libpf.PID, lb *labels.Builder) bool {
	lb.Set("__meta_agent_revision", p.revision)
	return true
}
