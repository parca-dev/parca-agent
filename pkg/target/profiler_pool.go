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

package target

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/pkg/labels"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
)

type Target struct {
	labelSet model.LabelSet
}

type Profiler interface {
	Labels() model.LabelSet
	LastProfileTakenAt() time.Time
	LastError() error
	Stop()
}

type ProfilerPool struct {
	ctx               context.Context
	mtx               *sync.RWMutex
	activeTargets     map[uint64]*Target
	activeProfilers   map[uint64]Profiler
	externalLabels    model.LabelSet
	logger            log.Logger
	ksymCache         *ksym.KsymCache
	writeClient       profilestorepb.ProfileStoreServiceClient
	debugInfoClient   debuginfo.Client
	profilingDuration time.Duration
	tmp               string
}

func NewProfilerPool(
	ctx context.Context,
	externalLabels model.LabelSet,
	logger log.Logger,
	ksymCache *ksym.KsymCache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	profilingDuration time.Duration,
	tmp string) *ProfilerPool {
	pp := &ProfilerPool{
		ctx:               ctx,
		mtx:               &sync.RWMutex{},
		activeTargets:     map[uint64]*Target{},
		activeProfilers:   map[uint64]Profiler{},
		externalLabels:    externalLabels,
		logger:            logger,
		ksymCache:         ksymCache,
		writeClient:       writeClient,
		debugInfoClient:   debugInfoClient,
		profilingDuration: profilingDuration,
		tmp:               tmp,
	}

	return pp
}

func (pp *ProfilerPool) Profilers() []Profiler {
	pp.mtx.RLock()
	defer pp.mtx.RUnlock()

	res := make([]Profiler, 0, len(pp.activeProfilers))
	for _, profiler := range pp.activeProfilers {
		res = append(res, profiler)
	}
	return res
}

func (pp *ProfilerPool) Sync(tg []*Group, reg prometheus.Registerer) {
	pp.mtx.Lock()
	defer pp.mtx.Unlock()

	newTargets := map[uint64]*Target{}

	for _, newTargetGroup := range tg {
		for _, t := range newTargetGroup.Targets {

			target := &Target{labelSet: model.LabelSet{}}

			for labelName, labelValue := range t {
				target.labelSet[labelName] = labelValue
			}

			for labelName, labelValue := range newTargetGroup.Labels {
				target.labelSet[labelName] = labelValue
			}

			for labelName, labelValue := range pp.externalLabels {
				target.labelSet[labelName] = labelValue
			}

			h := labelsetToLabels(target.labelSet).Hash()
			newTargets[h] = target
		}
	}

	//add new targets and profile them
	for _, newTarget := range newTargets {
		h := labelsetToLabels(newTarget.labelSet).Hash()

		if _, found := pp.activeTargets[h]; !found {
			newProfiler := profiler.NewCgroupProfiler(
				pp.logger,
				pp.ksymCache,
				pp.writeClient,
				pp.debugInfoClient,
				newTarget.labelSet,
				pp.profilingDuration,
				reg,
				pp.tmp,
			)

			go func() {
				err := newProfiler.Run(pp.ctx)
				level.Debug(pp.logger).Log("msg", "profiler ended with error", "error", err, "labels", newProfiler.Labels().String())
			}()

			pp.activeTargets[h] = newTarget
			pp.activeProfilers[h] = newProfiler
		}
	}

	// delete profiles no longer active
	for h := range pp.activeTargets {
		if _, found := newTargets[h]; !found {
			delete(pp.activeTargets, h)
			delete(pp.activeProfilers, h)
		}
	}
}

func labelsetToLabels(labelSet model.LabelSet) labels.Labels {
	ls := make(labels.Labels, 0, len(labelSet))
	for k, v := range labelSet {
		ls = append(ls, labels.Label{
			Name:  string(k),
			Value: string(v),
		})
	}
	sort.Sort(ls)
	return ls
}
