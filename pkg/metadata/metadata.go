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
//

package metadata

import (
	"errors"
	"sync"

	"github.com/prometheus/common/model"
)

type Provider interface {
	Labels(pid int) (model.LabelSet, error)
	Name() string
	ShouldCache() bool
}

type StatelessProvider struct {
	name      string
	labelFunc func(pid int) (model.LabelSet, error)
}

func (p *StatelessProvider) Labels(pid int) (model.LabelSet, error) {
	return p.labelFunc(pid)
}

func (p *StatelessProvider) Name() string {
	return p.name
}

func (p *StatelessProvider) ShouldCache() bool {
	return true
}

type StatefulProvider struct {
	name string

	mtx   *sync.RWMutex
	state map[int]model.LabelSet
}

func (p *StatefulProvider) Labels(pid int) (model.LabelSet, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.state == nil {
		return nil, errors.New("state not initialized")
	}

	v, ok := p.state[pid]
	if !ok {
		return model.LabelSet{}, errors.New("not found")
	}
	return v, nil
}

func (p *StatefulProvider) Name() string {
	return p.name
}

func (p *StatefulProvider) ShouldCache() bool {
	return false
}

func (p *StatefulProvider) update(state map[int]model.LabelSet) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.state = state
}
