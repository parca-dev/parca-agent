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
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/discovery"
)

// ServiceDiscovery metadata provider.
func ServiceDiscovery(logger log.Logger, m *discovery.Manager) Provider {
	provider := &StatefulProvider{
		name:  "service discovery",
		state: map[int]model.LabelSet{},
		mtx:   &sync.RWMutex{},
	}

	go func() {
		defer level.Warn(logger).Log("msg", "service discovery metadata provider exited")

		for tSets := range m.SyncCh() {
			state := map[int]model.LabelSet{}
			// Update process labels.
			for _, groups := range tSets {
				for _, group := range groups {
					for _, pid := range group.PIDs {
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
			}

			provider.update(state)
		}
	}()

	return provider
}
