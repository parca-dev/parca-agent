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
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

type Target struct{}

type Profiler interface {
	Labels() model.LabelSet
	LastSuccessfulProfileStartedAt() time.Time
	NextProfileStartedAt() time.Time
	LastError() error
	Stop()
}

type ProfilerPool struct {
	mtx               *sync.RWMutex
	activeTargets     map[uint64]*Target
	activeProfilers   map[string]Profiler
	externalLabels    model.LabelSet
	logger            log.Logger
	reg               prometheus.Registerer
	ksymCache         *ksym.Cache
	objCache          objectfile.Cache
	writeClient       profilestorepb.ProfileStoreServiceClient
	debugInfoClient   debuginfo.Client
	profilingDuration time.Duration
	samplingRatio     float64
}

func NewProfilerPool(
	logger log.Logger,
	reg prometheus.Registerer,
	ksymCache *ksym.Cache,
	objCache objectfile.Cache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	profilingDuration time.Duration,
	externalLabels model.LabelSet,
	samplingRatio float64,
) *ProfilerPool {
	return &ProfilerPool{
		mtx:               &sync.RWMutex{},
		activeTargets:     map[uint64]*Target{},
		activeProfilers:   map[string]Profiler{},
		externalLabels:    externalLabels,
		logger:            logger,
		reg:               reg,
		ksymCache:         ksymCache,
		objCache:          objCache,
		writeClient:       writeClient,
		debugInfoClient:   debugInfoClient,
		profilingDuration: profilingDuration,
		samplingRatio:     samplingRatio,
	}
}

func (pp *ProfilerPool) Profilers() map[string]Profiler {
	pp.mtx.RLock()
	defer pp.mtx.RUnlock()

	res := map[string]Profiler{}
	for name, profiler := range pp.activeProfilers {
		res[name] = profiler
	}

	return res
}

func (pp *ProfilerPool) AddProfiler(ctx context.Context, profilerFunc profiler.NewProfilerFunc) error {
	pp.mtx.Lock()
	defer pp.mtx.Unlock()

	labelSet := model.LabelSet{}
	newProfiler := profilerFunc(
		pp.logger,
		pp.reg,
		pp.ksymCache,
		pp.objCache,
		pp.writeClient,
		pp.debugInfoClient,
		labelSet,
		pp.profilingDuration,
	)
	go func() {
		err := newProfiler.Run(ctx)
		level.Warn(pp.logger).Log("msg", "profiler ended with error", "error", err, "profilerName", newProfiler.Name(), "labels", newProfiler.Labels().String())
	}()

	pp.activeProfilers[newProfiler.Name()] = newProfiler

	return nil
}
