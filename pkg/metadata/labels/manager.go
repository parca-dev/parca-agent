// Copyright 2022 The Parca Authors
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
	logger         log.Logger
	providers      []*metadata.Provider
	relabelConfigs []*relabel.Config
	mtx            *sync.RWMutex
	caches         map[string]cache.Cache
}

// New returns an initialized Manager.
func NewManager(logger log.Logger, providers []*metadata.Provider, relabelConfigs []*relabel.Config) *Manager {
	return &Manager{
		logger:         logger,
		providers:      providers,
		relabelConfigs: relabelConfigs,
		mtx:            &sync.RWMutex{},
		caches:         make(map[string]cache.Cache),
	}
}

// ApplyConfig updates the Manager's config.
func (m *Manager) ApplyConfig(relabelConfigs []*relabel.Config) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.relabelConfigs = relabelConfigs
	for _, cache := range m.caches {
		cache.InvalidateAll()
	}
	return nil
}

// InvalidateCachesForPIDs invalidate all label caches for given PIDs.
func (m *Manager) InvalidateCachesForPIDs(pids []int) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	for _, pid := range pids {
		for _, cache := range m.caches {
			cache.Invalidate(pid)
		}
		level.Debug(m.logger).Log("msg", "invalidated all label caches for process", "pid", pid)
	}
}

// labelSet fetches process specific labels to the profile.
// Returns nil if set is dropped.
func (m *Manager) labelSet(name string, pid uint64) model.LabelSet {
	labelSet := model.LabelSet{
		"__name__": model.LabelValue(name),
		"pid":      model.LabelValue(strconv.FormatUint(pid, 10)),
	}

	for _, provider := range m.providers {
		// Add service discovery metadata, such as the Kubernetes pod where the
		// process is running, among others.
		lbl, err := provider.Labels(int(pid))
		if err != nil {
			// NOTICE: Can be too noisy. Keeping this for debugging purposes.
			// level.Debug(p.logger).Log("msg", "failed to get metadata", "provider", provider.Name(), "err", err)
			continue
		}
		for k, v := range lbl {
			labelSet[k] = v
		}
	}

	return labelSet
}

func (m *Manager) processRelabel(lbls labels.Labels) labels.Labels {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return relabel.Process(lbls, m.relabelConfigs...)
}

// Labels returns a labels.Labels with relabel configs applied.
// Returns nil if set is dropped.
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

// getIfCached retrieved a labelSet if it has been cached.
func (m *Manager) getIfCached(profiler string, pid uint64) (model.LabelSet, bool) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if _, ok := m.caches[profiler]; ok {
		if lset, ok := m.caches[profiler].GetIfPresent(int(pid)); ok {
			labelSet, ok := lset.(model.LabelSet)
			if ok {
				level.Debug(m.logger).Log("msg", "label cache hit", "provider", profiler, "pid", pid)
				return labelSet, true
			}
			level.Error(m.logger).Log("msg", "failed to assert cached label set type", "profiler", profiler, "pid", pid)
		}
	}

	level.Debug(m.logger).Log("msg", "label cache miss", "provider", profiler, "pid", pid)
	return nil, false
}

// cache caches a given labelSet for a profiler/pid pair.
// It creates the cache for the provider if does not exist.
func (m *Manager) cache(profiler string, pid uint64, labelSet model.LabelSet) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, ok := m.caches[profiler]; !ok {
		m.caches[profiler] = cache.New(cache.WithExpireAfterAccess(10 * time.Minute))
	}

	m.caches[profiler].Put(int(pid), labelSet)
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
