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
	"hash/fnv"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

type Target struct {
	labelSet model.LabelSet
}

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
	activeProfilers   map[uint64]Profiler
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
		activeProfilers:   map[uint64]Profiler{},
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

func (pp *ProfilerPool) Profilers() []Profiler {
	pp.mtx.RLock()
	defer pp.mtx.RUnlock()

	res := make([]Profiler, 0, len(pp.activeProfilers))
	for _, profiler := range pp.activeProfilers {
		res = append(res, profiler)
	}
	return res
}

func (pp *ProfilerPool) Sync(ctx context.Context, tg []*Group) {
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

			if !probabilisticSampling(pp.samplingRatio, labelsetToLabels(target.labelSet)) {
				// This target is not being sampled.
				continue
			}
			newTargets[h] = target
		}
	}

	// Add new targets and profile them.
	for _, newTarget := range newTargets {
		h := labelsetToLabels(newTarget.labelSet).Hash()

		if _, found := pp.activeTargets[h]; !found {
			newProfiler := profiler.NewCgroupProfiler(
				pp.logger,
				pp.reg,
				pp.ksymCache,
				pp.objCache,
				pp.writeClient,
				pp.debugInfoClient,
				newTarget.labelSet,
				pp.profilingDuration,
			)

			go func() {
				err := newProfiler.Run(ctx)
				level.Warn(pp.logger).Log("msg", "profiler ended with error", "error", err, "labels", newProfiler.Labels().String())
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

func probabilisticSampling(ratio float64, labels labels.Labels) bool {
	seps := []byte{'\xff'}

	if ratio == 1.0 {
		return true
	}

	b := make([]byte, 0, 1024)
	for _, v := range labels {
		b = append(b, v.Name...)
		b = append(b, seps[0])
		b = append(b, v.Value...)
		b = append(b, seps[0])
	}
	h := fnv.New32a()
	h.Write(b)
	v := h.Sum32()
	return v <= uint32(float64(math.MaxUint32)*ratio)
}
