package metadata

import (
	"github.com/elastic/otel-profiling-agent/util"
	"github.com/prometheus/prometheus/model/labels"
)

type agentMetadataProvider struct {
	revision string
}

func NewAgentMetadataProvider(revision string) MetadataProvider {
	return &agentMetadataProvider{revision: revision}
}

func (p *agentMetadataProvider) AddMetadata(_ util.PID, lb *labels.Builder) {
	lb.Set("__meta_agent_revision", p.revision)
}
