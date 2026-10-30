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

// Package processlabels resolves the label set parca-agent attaches to a
// process and renders it as OTel semantic-convention resource attributes.
//
// It is shared by the profile reporter and GPU metrics so that a
// process's profiles and its GPU metrics carry the same identity: the same
// metadata providers, the same optional relabel config, and the same rendering
// as typed resource attributes.
package processlabels

import (
	"context"
	"strings"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// Result is a process's label set after relabelling. Keep is false when a
// relabel rule dropped the process, in which case nothing about it should be
// reported.
type Result struct {
	Labels labels.Labels
	Keep   bool
}

// Config configures a Resolver.
type Config struct {
	CacheSize      uint32
	LabelTTL       time.Duration
	NodeName       string
	RelabelConfigs []*relabel.Config
	Providers      []metadata.MetadataProvider
}

// Resolver produces per-process label sets: the node label, the metadata
// providers' output, relabel-config processing, then deletion of the
// __meta_* discovery labels. Results are cached per PID for the label TTL so
// long-lived processes still pick up metadata changes.
type Resolver struct {
	cfg            Config
	cache          *lru.SyncedLRU[libpf.PID, Result]
	providers      []metadata.MetadataProvider
	relabelConfigs []*relabel.Config
	nodeName       string
}

// New builds a Resolver.
func New(cfg Config) (*Resolver, error) {
	cache, err := lru.NewSynced[libpf.PID, Result](cfg.CacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}
	cache.SetLifetime(cfg.LabelTTL)
	return &Resolver{
		cfg:            cfg,
		cache:          cache,
		providers:      cfg.Providers,
		relabelConfigs: cfg.RelabelConfigs,
		nodeName:       cfg.NodeName,
	}, nil
}

// DefaultProviders returns parca-agent's metadata provider chain. executables
// is the profiler's executable-metadata cache; pass nil outside the profiler,
// which leaves out the main-executable provider. LocalOnly replaces Kubernetes
// and runtime discovery with procfs container ID and pod UID lookups. Providers emit
// semconv keys directly when configured for OTLP.
func DefaultProviders(ctx context.Context, nodeName, agentRevision string,
	executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo], cfg metadata.Config,
) ([]metadata.MetadataProvider, error) {
	var cmp metadata.MetadataProvider
	if cfg.LocalOnly {
		cmp = metadata.NewLocalContainerMetadataProvider()
	} else {
		var err error
		cmp, err = metadata.NewContainerMetadataProvider(ctx, nodeName, cfg)
		if err != nil {
			return nil, err
		}
	}
	sysMeta, err := metadata.NewSystemMetadataProvider(cfg)
	if err != nil {
		return nil, err
	}

	providers := []metadata.MetadataProvider{metadata.NewProcessMetadataProvider(cfg)}
	if executables != nil {
		providers = append(providers, metadata.NewMainExecutableMetadataProvider(executables, cfg))
	}
	if !cfg.Semconv || cfg.KeepDiscoveryLabels {
		providers = append(providers, metadata.NewAgentMetadataProvider(agentRevision))
	}
	return append(providers, cmp, sysMeta), nil
}

// Fork returns a Resolver with r's providers and relabel rules but a cache of
// its own, for a caller whose seed differs from r's: the cache is per PID, so
// sharing it would let one caller's seed leak into the other's results.
func (r *Resolver) Fork() (*Resolver, error) { return New(r.cfg) }

// RelabelConfigs returns the relabel rules the Resolver applies.
func (r *Resolver) RelabelConfigs() []*relabel.Config { return r.relabelConfigs }

// Resolve returns pid's labels. seed, if non-nil, sets labels before the
// providers run, so relabel rules can see them; since the result is cached per
// PID, seed must depend only on the process, not on the call.
func (r *Resolver) Resolve(ctx context.Context, pid libpf.PID, seed func(*labels.Builder)) Result {
	if res, ok := r.cache.Get(pid); ok {
		return res
	}

	lb := &labels.Builder{}
	lb.Set("node", r.nodeName)
	if seed != nil {
		seed(lb)
	}

	cacheable := true
	for _, p := range r.providers {
		cacheable = p.AddMetadata(ctx, pid, lb) && cacheable
	}

	keep := relabel.ProcessBuilder(lb, r.relabelConfigs...)

	// Meta labels are deleted after relabelling. Other internal labels
	// propagate to the target which decides whether they will be part of
	// their label set.
	lb.Range(func(lbl labels.Label) {
		if strings.HasPrefix(lbl.Name, model.MetaLabelPrefix) {
			lb.Del(lbl.Name)
		}
	})

	res := Result{Labels: lb.Labels(), Keep: keep}
	if cacheable {
		r.cache.Add(pid, res)
	}
	return res
}
