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
	"strings"
	"sync/atomic"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// processLabeler produces the Prometheus-style label set parca-agent attaches
// to every sample: per-PID metadata from the provider chain, relabel-config
// processing (which can drop a process outright), and the per-sample
// cpu/thread_id/thread_name patch.
//
// Every backend shares it so relabel drops cannot drift between them. The two
// label sets stay separate because arrow flattens them into one row while OTLP
// puts the process-invariant ones on the Resource.
type processLabeler struct {
	// labels caches the per-PID label set. Entries expire after the
	// configured label TTL so long-lived processes pick up metadata changes.
	labels *lru.SyncedLRU[libpf.PID, labelRetrievalResult]

	metadataProviders []metadata.MetadataProvider
	relabelConfigs    []*relabel.Config
	externalLabels    []Label
	nodeName          string

	// sampleLabels builds the per-sample patch (cpu, thread_id,
	// thread_name) and owns how each one is named and typed downstream.
	sampleLabels sampleLabeler

	// oomState is assigned after construction (oomprof.SetupWithReporter
	// needs the finished reporter), so it is an atomic rather than a plain
	// field: labelsForTID reads it concurrently with that write.
	oomState atomic.Pointer[oomprof.State]
}

// labelerConfig carries what newProcessLabeler needs. It mirrors the subset of
// reporter.Config that concerns labelling.
type labelerConfig struct {
	CacheSize              uint32
	LabelTTL               time.Duration
	NodeName               string
	AgentRevision          string
	RelabelConfigs         []*relabel.Config
	ExternalLabels         []Label
	DisableCPULabel        bool
	DisableThreadIDLabel   bool
	DisableThreadCommLabel bool

	// Executables is the shared executable-metadata cache. The
	// main-executable metadata provider reads it, so both the labeler and
	// the execTracker hold the same LRU.
	Executables *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo]
}

func newProcessLabeler(cfg labelerConfig) (*processLabeler, error) {
	lbls, err := lru.NewSynced[libpf.PID, labelRetrievalResult](cfg.CacheSize, libpf.PID.Hash32)
	if err != nil {
		return nil, err
	}
	lbls.SetLifetime(cfg.LabelTTL)

	cmp, err := metadata.NewContainerMetadataProvider(context.TODO(), cfg.NodeName)
	if err != nil {
		return nil, err
	}

	sysMeta, err := metadata.NewSystemMetadataProvider()
	if err != nil {
		return nil, err
	}

	return &processLabeler{
		labels: lbls,
		metadataProviders: []metadata.MetadataProvider{
			metadata.NewProcessMetadataProvider(),
			metadata.NewMainExecutableMetadataProvider(cfg.Executables),
			metadata.NewAgentMetadataProvider(cfg.AgentRevision),
			cmp,
			sysMeta,
		},
		relabelConfigs: cfg.RelabelConfigs,
		externalLabels: cfg.ExternalLabels,
		nodeName:       cfg.NodeName,
		sampleLabels:   newSampleLabeler(cfg),
	}, nil
}

// SetOOMState wires the oomprof state in after construction so labelsForTID can
// stamp job="oomprof" on processes the OOM killer touched.
func (l *processLabeler) SetOOMState(s *oomprof.State) {
	l.oomState.Store(s)
}

func (l *processLabeler) addMetadataForPID(ctx context.Context, pid libpf.PID, lb *labels.Builder) bool {
	cache := true

	for _, p := range l.metadataProviders {
		cacheable := p.AddMetadata(ctx, pid, lb)
		cache = cache && cacheable
	}

	return cache
}

func (l *processLabeler) labelsForTID(tid, pid libpf.PID, comm libpf.Comm, cpu uint32, origin libpf.Origin, envVars map[libpf.String]libpf.String) labelRetrievalResult {
	cached, hit := l.labels.Get(pid)

	if !hit {
		lb := &labels.Builder{}
		lb.Set("node", l.nodeName)

		for k, v := range envVars {
			lb.Set("__meta_env_var_"+k.String(), v.String())
		}

		if s := l.oomState.Load(); s != nil && s.PidOomd(uint32(pid)) {
			lb.Set("job", "oomprof")
		}

		cacheable := l.addMetadataForPID(context.TODO(), pid, lb)

		keep := relabel.ProcessBuilder(lb, l.relabelConfigs...)

		// Meta labels are deleted after relabelling. Other internal labels propagate to
		// the target which decides whether they will be part of their label set.
		lb.Range(func(lbl labels.Label) {
			if strings.HasPrefix(lbl.Name, model.MetaLabelPrefix) {
				lb.Del(lbl.Name)
			}
		})

		cached = labelRetrievalResult{
			resource: lb.Labels(),
			keep:     keep,
		}

		if cacheable {
			log.Debugf("adding labels for PID %d to cache: %s", pid, cached.resource)
			l.labels.Add(pid, cached)
		}
	}

	// Skip per-sample label patching if relabeling dropped this process.
	if !cached.keep {
		return cached
	}

	// Probe samples additionally run through a per-sample relabel pass so
	// rules can derive custom labels (or drop) from per-sample fields. We
	// gate this on probe origin only -- CPU/off-CPU/memory/cuda samples
	// keep the cheap "patch and ship" path (see commit 34c9ed7a).
	perSampleRelabel := origin == support.TraceOriginProbe && len(l.relabelConfigs) > 0

	// Nothing per-sample to do: no patches and no per-sample relabel.
	if !l.sampleLabels.enabled() && !perSampleRelabel {
		return cached
	}

	// The per-sample set stays separate from the process-invariant one so
	// the OTLP backend can put it on the Sample rather than the Resource.
	res := labelRetrievalResult{
		resource: cached.resource,
		sample:   l.sampleLabels.build(tid, comm, cpu),
		keep:     true,
	}

	// The relabeler works on one flat set, so probe samples get both sets
	// merged, relabeled, and the per-sample names split back out.
	if perSampleRelabel {
		lb := labels.NewBuilder(cached.resource)
		res.sample.Range(func(lbl labels.Label) {
			lb.Set(lbl.Name, lbl.Value)
		})

		keep := relabel.ProcessBuilder(lb, l.relabelConfigs...)
		lb.Range(func(lbl labels.Label) {
			if strings.HasPrefix(lbl.Name, model.MetaLabelPrefix) {
				lb.Del(lbl.Name)
			}
		})

		resource, sample := l.sampleLabels.split(lb.Labels())
		res = labelRetrievalResult{
			resource: resource,
			sample:   sample,
			keep:     keep,
		}
	}

	return res
}
