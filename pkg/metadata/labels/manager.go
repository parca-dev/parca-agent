// Copyright 2022-2023 The Parca Authors
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

package labels

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/metadata"
)

// Manager is responsible for aggregating, mutating, and serving process labels.
type Manager struct {
	logger log.Logger

	providers     []metadata.Provider
	providerCache burrow.Cache

	mtx            *sync.RWMutex
	relabelConfigs []*relabel.Config

	labelCache burrow.Cache
}

// New returns an initialized Manager.
func NewManager(logger log.Logger, reg prometheus.Registerer, providers []metadata.Provider, relabelConfigs []*relabel.Config, profilingDuration time.Duration) *Manager {
	return &Manager{
		logger:    logger,
		providers: providers,

		mtx:            &sync.RWMutex{},
		relabelConfigs: relabelConfigs,

		labelCache: burrow.New(
			// NOTICE: ProcessInfoManager also caches labels.
			// This cache will be useful for UI labels and retries for process info.
			burrow.WithExpireAfterAccess(profilingDuration*3),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "label")),
		),
		// Making cache durations shorter than label cache will not make any visible difference.
		providerCache: burrow.New(
			burrow.WithExpireAfterWrite(profilingDuration*6*10),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "label_provider")),
		),
	}
}

// ApplyConfig updates the Manager's config.
func (m *Manager) ApplyConfig(relabelConfigs []*relabel.Config) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.relabelConfigs = relabelConfigs
	m.labelCache.InvalidateAll()
	return nil
}

// labelSet fetches process specific labels to the profile.
// Returns nil if set is dropped.
func (m *Manager) labelSet(pid int) model.LabelSet {
	labelSet := model.LabelSet{
		"pid": model.LabelValue(strconv.Itoa(pid)),
	}

	for _, provider := range m.providers {
		shouldCache := provider.ShouldCache()
		if shouldCache {
			key := providerCacheKey(provider.Name(), pid)
			if cached, ok := m.providerCache.GetIfPresent(key); ok {
				lbls, ok := cached.(model.LabelSet)
				if ok {
					labelSet = labelSet.Merge(lbls)
					continue
				}
				level.Error(m.logger).Log("msg", "failed to assert cached label set type", "pid", pid)
				m.providerCache.Invalidate(key)
			}
		}

		// Add service discovery metadata, such as the Kubernetes pod where the
		// process is running, among others.
		lbl, err := provider.Labels(pid)
		if err != nil {
			// NOTICE: Can be too noisy. Keeping this for debugging purposes.
			// level.Debug(p.logger).Log("msg", "failed to get metadata", "provider", provider.Name(), "err", err)
			continue
		}
		labelSet = labelSet.Merge(lbl)

		if shouldCache {
			// Stateless providers are cached for a longer period of time.
			m.providerCache.Put(providerCacheKey(provider.Name(), pid), labelSet)
		}
	}

	return labelSet
}

// Labels returns a labels.Labels with relabel configs applied.
// Returns nil if set is dropped.
// This method is only used by the UI for troubleshooting.
func (m *Manager) Labels(pid int) labels.Labels {
	labelSet, ok := m.getIfCached(pid)
	if ok {
		if labelSet == nil {
			return nil
		}
		return labelSetToLabels(labelSet)
	}

	lbls, keep := labelSetToLabels(m.labelSet(pid)), true

	if len(m.relabelConfigs) > 0 {
		lbls, keep = m.processRelabel(lbls)
	}

	// This path is only used by the UI for troubleshooting,
	// it is not necessary to cache these labels at the moment
	if !keep {
		return nil
	}
	return lbls
}

// LabelSet returns a model.LabelSet with relabel configs applied.
func (m *Manager) LabelSet(pid int) model.LabelSet {
	labelSet, ok := m.getIfCached(pid)
	if ok {
		return labelSet
	}

	labelSet = m.labelSet(pid)

	if len(m.relabelConfigs) > 0 {
		lbls, keep := m.processRelabel(labelSetToLabels(labelSet))
		if !keep {
			m.labelCache.Put(labelCacheKey(pid), model.LabelSet{})
			return nil
		}

		labelSet = labelsToLabelSet(lbls)
	}

	m.labelCache.Put(labelCacheKey(pid), labelSet)
	return labelSet
}

func (m *Manager) processRelabel(lbls labels.Labels) (labels.Labels, bool) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return relabel.Process(lbls, m.relabelConfigs...)
}

func labelCacheKey(pid int) string {
	return strconv.Itoa(pid)
}

func providerCacheKey(provider string, pid int) string {
	return fmt.Sprintf("%s:%d", provider, pid)
}

// getIfCached retrieved a labelSet if it has been cached.
func (m *Manager) getIfCached(pid int) (model.LabelSet, bool) {
	if lset, ok := m.labelCache.GetIfPresent(labelCacheKey(pid)); ok {
		labelSet, ok := lset.(model.LabelSet)
		if ok {
			return labelSet, true
		}
		level.Error(m.logger).Log("msg", "failed to assert cached label set type", "pid", pid)
	}

	return nil, false
}

// labelSetToLabels converts a model.LabelSet to labels.Labels.
func labelSetToLabels(labelSet model.LabelSet) labels.Labels {
	b := labels.NewScratchBuilder(len(labelSet))
	for name, value := range labelSet {
		b.Add(string(name), string(value))
	}
	return b.Labels()
}

// labelsToLabelSet converts a labels.Labels to model.LabelSet.
func labelsToLabelSet(lbls labels.Labels) model.LabelSet {
	labelSet := make(model.LabelSet, len(lbls))
	for _, l := range lbls {
		labelSet[model.LabelName(l.Name)] = model.LabelValue(l.Value)
	}
	return labelSet
}
