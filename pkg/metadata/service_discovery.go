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
//

package metadata

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/process"
)

type ServiceDiscoveryProvider struct {
	logger log.Logger

	mtx   *sync.RWMutex
	state map[int]model.LabelSet

	tree        *process.Tree
	discoveryCh <-chan map[string][]*discovery.Group
}

func (p *ServiceDiscoveryProvider) Name() string {
	return "service_discovery"
}

func (p *ServiceDiscoveryProvider) ShouldCache() bool {
	return false
}

func (p *ServiceDiscoveryProvider) Labels(ctx context.Context, pid int) (model.LabelSet, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	pids, err := p.tree.FindAllAncestorProcessIDsInSameCgroup(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to find all ancestor process IDs in same cgroup: %w", err)
	}

	p.mtx.RLock()
	state := p.state
	p.mtx.RUnlock()

	if state == nil {
		return nil, errors.New("state not initialized")
	}

	for _, pid := range append(pids, pid) {
		v, ok := state[pid]
		if ok {
			return v, nil
		}
	}

	return model.LabelSet{}, errors.New("not found")
}

// ServiceDiscovery metadata provider.
func ServiceDiscovery(logger log.Logger, ch <-chan map[string][]*discovery.Group, psTree *process.Tree) *ServiceDiscoveryProvider {
	return &ServiceDiscoveryProvider{
		logger:      logger,
		state:       map[int]model.LabelSet{},
		mtx:         &sync.RWMutex{},
		tree:        psTree,
		discoveryCh: ch,
	}
}

func (p *ServiceDiscoveryProvider) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case tSets := <-p.discoveryCh:
			level.Debug(p.logger).Log("msg", "received new service discovery targets", "targets", fmt.Sprintf("%+v", tSets))
			state := map[int]model.LabelSet{}
			// Update process labels.
			for _, groups := range tSets {
				for _, group := range groups {
					pid := group.EntryPID
					// Overwrite the information we have here with the latest.
					allLabels := model.LabelSet{}
					for k, v := range group.Labels {
						allLabels[k] = v
					}
					for _, t := range group.Targets {
						for k, v := range t {
							allLabels[k] = v
						}
					}

					_, ok := state[pid]
					if ok {
						state[pid] = state[pid].Merge(allLabels)
					} else {
						state[pid] = allLabels
					}
				}
			}

			p.mtx.Lock()
			p.state = state
			p.mtx.Unlock()
		}
	}
}
