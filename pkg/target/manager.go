// Copyright (c) 2022 The Parca Authors
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
//

package target

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type Manager struct {
	mtx               *sync.RWMutex
	profilerPools     map[string]*ProfilerPool
	logger            log.Logger
	reg               prometheus.Registerer
	externalLabels    model.LabelSet
	ksymCache         *ksym.Cache
	writeClient       profilestorepb.ProfileStoreServiceClient
	debugInfoClient   debuginfo.Client
	profilingDuration time.Duration
	samplingRatio     float64
}

func NewManager(
	logger log.Logger,
	reg prometheus.Registerer,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	profilingDuration time.Duration,
	externalLabels model.LabelSet,
	samplingRatio float64,
) *Manager {
	return &Manager{
		mtx:               &sync.RWMutex{},
		profilerPools:     map[string]*ProfilerPool{},
		logger:            logger,
		reg:               reg,
		externalLabels:    externalLabels,
		ksymCache:         ksym.NewKsymCache(logger),
		writeClient:       writeClient,
		debugInfoClient:   debugInfoClient,
		profilingDuration: profilingDuration,
		samplingRatio:     samplingRatio,
	}
}

func (m *Manager) Run(ctx context.Context, update <-chan map[string][]*Group) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case targetSets := <-update:
			err := m.reconcileTargets(ctx, targetSets)
			if err != nil {
				return err
			}
		}
	}
}

func (m *Manager) reconcileTargets(ctx context.Context, targetSets map[string][]*Group) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	level.Debug(m.logger).Log("msg", "reconciling targets")
	for name, targetSet := range targetSets {
		pp, found := m.profilerPools[name]
		if !found {
			// An arbitrary coefficient. Number of assumed object files per target.
			cacheSize := len(targetSet) * 5
			pp = NewProfilerPool(
				m.logger, m.reg,
				m.ksymCache, objectfile.NewCache(cacheSize),
				m.writeClient, m.debugInfoClient,
				m.profilingDuration, m.externalLabels,
				m.samplingRatio,
			)
			m.profilerPools[name] = pp
		}

		pp.Sync(ctx, targetSet)
	}
	return nil
}

func (m *Manager) ActiveProfilers() map[string][]Profiler {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	profilerSet := map[string][]Profiler{}
	for name, profilerPool := range m.profilerPools {
		profilerSet[name] = profilerPool.Profilers()
	}

	return profilerSet
}
