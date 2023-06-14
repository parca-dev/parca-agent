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
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/metadata"
)

type Cache[K comparable, V any] interface {
	Add(K, V)
	Get(K) (V, bool)
	Peek(K) (V, bool)
	Purge()
}

// Manager is responsible for aggregating, mutating, and serving process labels.
type Manager struct {
	logger log.Logger
	tracer trace.Tracer

	providers     []metadata.Provider
	providerCache Cache[string, model.LabelSet]
	labelCache    Cache[string, model.LabelSet]

	mtx            *sync.RWMutex
	relabelConfigs []*relabel.Config
}

// New returns an initialized Manager.
func NewManager(
	logger log.Logger,
	tracer trace.Tracer,
	reg prometheus.Registerer,
	providers []metadata.Provider,
	relabelConfigs []*relabel.Config,
	cacheDisabled bool,
	profilingDuration time.Duration,
) *Manager {
	var (
		labelCache    Cache[string, model.LabelSet] = cache.NewNoopCache[string, model.LabelSet]()
		providerCache Cache[string, model.LabelSet] = cache.NewNoopCache[string, model.LabelSet]()
	)
	if !cacheDisabled {
		labelCache = cache.NewLRUCacheWithTTL[string, model.LabelSet](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "label"}, reg),
			1024,
			3*profilingDuration,
		)
		// Making cache durations shorter than label cache will not make any visible difference.
		providerCache = cache.NewLRUCacheWithTTL[string, model.LabelSet](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "label_provider"}, reg),
			1024,
			10*6*profilingDuration,
		)
	}
	return &Manager{
		logger:    logger,
		tracer:    tracer,
		providers: providers,

		mtx:            &sync.RWMutex{},
		relabelConfigs: relabelConfigs,

		labelCache:    labelCache,
		providerCache: providerCache,
	}
}

// ApplyConfig updates the Manager's config.
func (m *Manager) ApplyConfig(relabelConfigs []*relabel.Config) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.relabelConfigs = relabelConfigs
	m.labelCache.Purge()
	return nil
}

// labelSet fetches process specific labels to the profile.
// Returns nil if set is dropped.
func (m *Manager) labelSet(ctx context.Context, pid int) (model.LabelSet, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	ctx, span := m.tracer.Start(ctx, "LabelManager.labelSet")
	defer span.End()

	labelSet := model.LabelSet{
		"pid": model.LabelValue(strconv.Itoa(pid)),
	}

	for _, provider := range m.providers {
		_, span := m.tracer.Start(ctx, fmt.Sprintf("LabelManager.labelSet/%s", provider.Name()))
		shouldCache := provider.ShouldCache()
		if shouldCache {
			span.SetAttributes(attribute.Bool("cache", true))
			key := providerCacheKey(provider.Name(), pid)
			if lbls, ok := m.providerCache.Get(key); ok {
				labelSet = labelSet.Merge(lbls)
				span.End()
				continue
			}
		}

		// Add service discovery metadata, such as the Kubernetes pod where the
		// process is running, among others.
		lbl, err := provider.Labels(ctx, pid)
		if err != nil {
			// NOTICE: Can be too noisy. Keeping this for debugging purposes.
			// level.Debug(p.logger).Log("msg", "failed to get metadata", "provider", provider.Name(), "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.End()
			continue
		}
		labelSet = labelSet.Merge(lbl)

		if shouldCache {
			// Stateless providers are cached for a longer period of time.
			m.providerCache.Add(providerCacheKey(provider.Name(), pid), labelSet)
		}
	}

	return labelSet, nil
}

// Labels returns a labels.Labels with relabel configs applied.
// Returns nil if set is dropped.
// This method is only used by the UI for troubleshooting.
func (m *Manager) Labels(ctx context.Context, pid int) (labels.Labels, error) {
	ctx, span := m.tracer.Start(ctx, "LabelManager.Labels")
	defer span.End()

	labelSet, ok := m.getIfCached(pid)
	if ok {
		if labelSet == nil {
			return nil, nil
		}
		return labelSetToLabels(labelSet), nil
	}

	labelSet, err := m.labelSet(ctx, pid)
	if err != nil {
		return nil, err
	}
	lbls, keep := labelSetToLabels(labelSet), true

	if len(m.relabelConfigs) > 0 {
		lbls, keep = m.processRelabel(lbls)
	}

	// This path is only used by the UI for troubleshooting,
	// it is not necessary to cache these labels at the moment
	if !keep {
		return nil, nil
	}
	return lbls, nil
}

// Fetch fetches process specific labels to the profile.
// This method is intended to be used by process info manager to fetch certain labels as early as possible.
// It bypasses relabeling and top-level caching.
func (m *Manager) Fetch(ctx context.Context, pid int) error {
	_, err := m.labelSet(ctx, pid)
	return err
}

// LabelSet returns a model.LabelSet with relabel configs applied.
func (m *Manager) LabelSet(ctx context.Context, pid int) (model.LabelSet, error) {
	labelSet, ok := m.getIfCached(pid)
	if ok {
		return labelSet, nil
	}

	labelSet, err := m.labelSet(ctx, pid)
	if err != nil {
		return nil, err
	}

	if len(m.relabelConfigs) > 0 {
		lbls, keep := m.processRelabel(labelSetToLabels(labelSet))
		if !keep {
			m.labelCache.Add(labelCacheKey(pid), model.LabelSet{})
			return nil, nil
		}

		labelSet = labelsToLabelSet(lbls)
	}

	m.labelCache.Add(labelCacheKey(pid), labelSet)
	return labelSet, nil
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
	if labelSet, ok := m.labelCache.Get(labelCacheKey(pid)); ok {
		return labelSet, true
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
