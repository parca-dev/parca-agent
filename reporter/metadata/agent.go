package metadata

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"github.com/prometheus/prometheus/model/labels"
)

type agentMetadataProvider struct {
	revision string
}

func NewAgentMetadataProvider(revision string) MetadataProvider {
	return &agentMetadataProvider{revision: revision}
}

func (p *agentMetadataProvider) AddMetadata(_ libpf.PID, lb *labels.Builder) bool {
	lb.Set("__meta_agent_revision", p.revision)
	return true
}
