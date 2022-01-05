// Copyright 2021 The Parca Authors
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

package target

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
)

type Manager struct {
	mtx               *sync.RWMutex
	profilerPools     map[string]*ProfilerPool
	logger            log.Logger
	externalLabels    model.LabelSet
	ksymCache         *ksym.KsymCache
	writeClient       profilestorepb.ProfileStoreServiceClient
	debugInfoClient   debuginfo.Client
	profilingDuration time.Duration
	tmp               string
}

func NewManager(
	logger log.Logger,
	externalLabels model.LabelSet,
	ksymCache *ksym.KsymCache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	profilingDuration time.Duration,
	tmp string) *Manager {
	m := &Manager{
		mtx:               &sync.RWMutex{},
		profilerPools:     map[string]*ProfilerPool{},
		logger:            logger,
		externalLabels:    externalLabels,
		ksymCache:         ksymCache,
		writeClient:       writeClient,
		debugInfoClient:   debugInfoClient,
		profilingDuration: profilingDuration,
		tmp:               tmp,
	}

	return m
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
			pp = NewProfilerPool(ctx, m.externalLabels, m.logger, m.ksymCache, m.writeClient, m.debugInfoClient, m.profilingDuration, m.tmp)
			m.profilerPools[name] = pp
		}

		pp.Sync(targetSet)
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
