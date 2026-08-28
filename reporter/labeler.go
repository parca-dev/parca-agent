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
	"fmt"
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
// It is shared by every export backend so the label semantics -- especially
// relabel drops -- cannot drift between them. The arrow backends flatten
// resource and sample labels into one row; the OTLP backend needs them
// separated (process-invariant labels belong on the OTLP Resource), which is
// why labelRetrievalResult carries the two sets rather than a single merged
// one.
type processLabeler struct {
	// labels caches the per-PID label set. Entries expire after the
	// configured label TTL so long-lived processes pick up metadata changes.
	labels *lru.SyncedLRU[libpf.PID, labelRetrievalResult]

	metadataProviders []metadata.MetadataProvider
	relabelConfigs    []*relabel.Config
	externalLabels    []Label
	nodeName          string

	// Per-sample label disable flags.
	disableCPULabel        bool
	disableThreadIDLabel   bool
	disableThreadCommLabel bool

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
		relabelConfigs:         cfg.RelabelConfigs,
		externalLabels:         cfg.ExternalLabels,
		nodeName:               cfg.NodeName,
		disableCPULabel:        cfg.DisableCPULabel,
		disableThreadIDLabel:   cfg.DisableThreadIDLabel,
		disableThreadCommLabel: cfg.DisableThreadCommLabel,
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

func (l *processLabeler) labelsForTID(tid, pid libpf.PID, comm libpf.String, cpu uint32, origin libpf.Origin, envVars map[libpf.String]libpf.String) labelRetrievalResult {
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
	if l.disableCPULabel && l.disableThreadIDLabel && l.disableThreadCommLabel &&
		!perSampleRelabel {
		return cached
	}

	// Build the per-sample label set. These stay separate from the
	// process-invariant set so the OTLP backend can put them on the Sample
	// rather than the Resource.
	sb := labels.NewScratchBuilder(3)
	if !l.disableCPULabel {
		sb.Add("cpu", fmt.Sprint(cpu))
	}
	if !l.disableThreadIDLabel {
		sb.Add("thread_id", fmt.Sprint(tid))
	}
	if !l.disableThreadCommLabel {
		sb.Add("thread_name", comm.String())
	}
	sb.Sort()

	res := labelRetrievalResult{
		resource: cached.resource,
		sample:   sb.Labels(),
		keep:     true,
	}

	// Per-sample relabel pass for probe samples. The per-PID pass already
	// ran against cached metadata; here the relabeler additionally sees
	// the final label names (thread_id, thread_name, cpu). Rules that only
	// consume per-PID inputs are idempotent across the two passes.
	//
	// The relabeler works on one flat set, so for probe samples the two
	// sets are merged, relabeled, and the result attributed to the
	// resource with the three known per-sample names split back out. A rule
	// that renames one of those three moves it to the resource, which is
	// the conservative choice: it stays on the profile rather than being
	// dropped.
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

		merged := lb.Labels()
		resource := labels.NewBuilder(merged)
		sample := labels.NewScratchBuilder(3)
		for _, name := range perSampleLabelNames {
			if v := merged.Get(name); v != "" {
				sample.Add(name, v)
				resource.Del(name)
			}
		}
		sample.Sort()

		res = labelRetrievalResult{
			resource: resource.Labels(),
			sample:   sample.Labels(),
			keep:     keep,
		}
	}

	return res
}

// perSampleLabelNames are the labels labelsForTID patches per sample rather
// than per process. They belong on the OTLP Sample, not the Resource.
var perSampleLabelNames = [...]string{"cpu", "thread_id", "thread_name"}
