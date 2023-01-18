// Copyright 2022 The Parca Authors
// TODO: This license is not consistent with license used in the project.
//       Delete the inconsistent license and above line and rerun pre-commit to insert a good license.
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
	"github.com/goburrow/cache"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"

	"github.com/parca-dev/parca-agent/pkg/metadata"
)

// Manager is responsible for aggregating, mutating, and serving process labels.
type Manager struct {
	logger log.Logger

	providers     []metadata.Provider
	providerCache cache.Cache

	mtx            *sync.RWMutex
	relabelConfigs []*relabel.Config

	labelCache cache.Cache
}

// New returns an initialized Manager.
func NewManager(logger log.Logger, providers []metadata.Provider, relabelConfigs []*relabel.Config, profilingDuration time.Duration) *Manager {
	return &Manager{
		logger:    logger,
		providers: providers,

		mtx:            &sync.RWMutex{},
		relabelConfigs: relabelConfigs,

		labelCache: cache.New(cache.WithExpireAfterWrite(profilingDuration * 3)),
		// Making cache durations shorter than label cache will not make any visible difference.
		providerCache: cache.New(cache.WithExpireAfterWrite(profilingDuration * 6 * 10)),
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
func (m *Manager) labelSet(name string, pid uint64) model.LabelSet {
	labelSet := model.LabelSet{
		"__name__": model.LabelValue(name),
		"pid":      model.LabelValue(strconv.FormatUint(pid, 10)),
	}

	for _, provider := range m.providers {
		shouldCache := provider.ShouldCache()
		if shouldCache {
			key := providerCacheKey(name, provider.Name(), pid)
			if cached, ok := m.providerCache.GetIfPresent(key); ok {
				lbls, ok := cached.(model.LabelSet)
				if ok {
					labelSet = labelSet.Merge(lbls)
					continue
				}
				level.Error(m.logger).Log("msg", "failed to assert cached label set type", "profiler", name, "pid", pid)
				m.providerCache.Invalidate(key)
			}
		}

		// Add service discovery metadata, such as the Kubernetes pod where the
		// process is running, among others.
		lbl, err := provider.Labels(int(pid))
		if err != nil {
			// NOTICE: Can be too noisy. Keeping this for debugging purposes.
			// level.Debug(p.logger).Log("msg", "failed to get metadata", "provider", provider.Name(), "err", err)
			continue
		}
		labelSet = labelSet.Merge(lbl)

		if shouldCache {
			// Stateless providers are cached for a longer period of time.
			m.providerCache.Put(providerCacheKey(name, provider.Name(), pid), labelSet)
		}
	}

	return labelSet
}

// Labels returns a labels.Labels with relabel configs applied.
// Returns nil if set is dropped.
// This method is only used by the UI for troubleshooting.
func (m *Manager) Labels(name string, pid uint64) labels.Labels {
	labelSet, ok := m.getIfCached(name, pid)
	if ok {
		if labelSet == nil {
			return nil
		}
		return labelSetToLabels(labelSet)
	}

	lbls := labelSetToLabels(m.labelSet(name, pid))

	if len(m.relabelConfigs) > 0 {
		lbls = m.processRelabel(lbls)
	}

	// This path is only used by the UI for troubleshooting,
	// it is not necessary to cache these labels at the moment
	return lbls
}

// LabelSet returns a model.LabelSet with relabel configs applied.
func (m *Manager) LabelSet(name string, pid uint64) model.LabelSet {
	labelSet, ok := m.getIfCached(name, pid)
	if ok {
		return labelSet
	}

	labelSet = m.labelSet(name, pid)

	if len(m.relabelConfigs) > 0 {
		lbls := m.processRelabel(labelSetToLabels(labelSet))
		if lbls == nil {
			m.cache(name, pid, nil)
			return nil
		}

		labelSet = labelsToLabelSet(lbls)
	}

	m.cache(name, pid, labelSet)
	return labelSet
}

func (m *Manager) processRelabel(lbls labels.Labels) labels.Labels {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return relabel.Process(lbls, m.relabelConfigs...)
}

func labelCacheKey(profiler string, pid uint64) string {
	return fmt.Sprintf("%s:%d", profiler, pid)
}

func providerCacheKey(profiler, provider string, pid uint64) string {
	return fmt.Sprintf("%s:%s:%d", profiler, provider, pid)
}

// getIfCached retrieved a labelSet if it has been cached.
func (m *Manager) getIfCached(profiler string, pid uint64) (model.LabelSet, bool) {
	if lset, ok := m.labelCache.GetIfPresent(labelCacheKey(profiler, pid)); ok {
		labelSet, ok := lset.(model.LabelSet)
		if ok {
			level.Debug(m.logger).Log("msg", "label cache hit", "provider", profiler, "pid", pid)
			return labelSet, true
		}
		level.Error(m.logger).Log("msg", "failed to assert cached label set type", "profiler", profiler, "pid", pid)
	}

	level.Debug(m.logger).Log("msg", "label cache miss", "provider", profiler, "pid", pid)
	return nil, false
}

// cache caches a given labelSet for a profiler/pid pair.
// It creates the cache for the provider if does not exist.
func (m *Manager) cache(profiler string, pid uint64, labelSet model.LabelSet) {
	m.labelCache.Put(labelCacheKey(profiler, pid), labelSet)
}

// labelSetToLabels converts a model.LabelSet to labels.Labels.
func labelSetToLabels(labelSet model.LabelSet) labels.Labels {
	lbls := make(labels.Labels, 0, len(labelSet))
	for name, value := range labelSet {
		lbls = append(lbls, labels.Label{Name: string(name), Value: string(value)})
	}
	return lbls
}

// labelsToLabelSet converts a labels.Labels to model.LabelSet.
func labelsToLabelSet(lbls labels.Labels) model.LabelSet {
	labelSet := make(model.LabelSet, len(lbls))
	for _, l := range lbls {
		labelSet[model.LabelName(l.Name)] = model.LabelValue(l.Value)
	}
	return labelSet
}
