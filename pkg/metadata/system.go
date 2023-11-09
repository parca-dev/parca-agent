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
	"sync"

	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/buildinfo"
	"github.com/parca-dev/parca-agent/pkg/kernel"
)

var (
	labels model.LabelSet
	once   sync.Once
)

type systemProvider struct {
	StatelessProvider
}

func (p *systemProvider) ShouldCache() bool {
	// Uses its own cache.
	return false
}

// System provides metadata for the current system.
func System() Provider {
	once.Do(setMetadata)

	return &systemProvider{StatelessProvider{"system", func(ctx context.Context, _ int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return labels, nil
	}}}
}

const unknown = "unknown"

// Call the system metadata getters just once as they will not
// change while the Agent is running.
func setMetadata() {
	var (
		release      = unknown
		revision     = unknown
		architecture = unknown
	)

	r, err := kernel.Release()
	if err == nil {
		release = r
	}

	m, err := kernel.Machine()
	if err == nil {
		architecture = m
	}

	b, err := buildinfo.FetchBuildInfo()
	if err == nil {
		revision = b.VcsRevision
	}
	labels = model.LabelSet{
		"kernel_release": model.LabelValue(release),
		"agent_revision": model.LabelValue(revision),
		"arch":           model.LabelValue(architecture),
	}
}
