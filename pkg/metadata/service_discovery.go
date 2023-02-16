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
	"errors"
	"fmt"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/process"
)

type serviceDiscoveryProvider struct {
	StatefulProvider
}

func (p *serviceDiscoveryProvider) Labels(pid int) (model.LabelSet, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.state == nil {
		return nil, errors.New("state not initialized")
	}

	tree, err := process.NewTree()
	if err != nil {
		return nil, fmt.Errorf("failed to create process tree: %w", err)
	}

	pids, err := tree.FindAllAncestorProcessIDsInSameCgroup(pid)
	if err != nil {
		return nil, err
	}

	for _, pid := range append(pids, pid) {
		v, ok := p.state[pid]
		if ok {
			return v, nil
		}
	}
	return model.LabelSet{}, errors.New("not found")
}

// ServiceDiscovery metadata provider.
func ServiceDiscovery(logger log.Logger, m *discovery.Manager) Provider {
	provider := &serviceDiscoveryProvider{
		StatefulProvider: StatefulProvider{
			name:  "service_discovery",
			state: map[int]model.LabelSet{},
			mtx:   &sync.RWMutex{},
		},
	}

	go func() {
		defer level.Warn(logger).Log("msg", "service discovery metadata provider exited")

		for tSets := range m.SyncCh() {
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

			provider.update(state)
		}
	}()

	return provider
}
