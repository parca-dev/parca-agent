// Copyright 2022-2024 The Parca Authors
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

	"github.com/prometheus/common/model"
)

type Provider interface {
	Labels(ctx context.Context, pid int) (model.LabelSet, error)
	Name() string
	ShouldCache() bool
}

type StatelessProvider struct {
	name      string
	labelFunc func(ctx context.Context, pid int) (model.LabelSet, error)
}

func (p *StatelessProvider) Labels(ctx context.Context, pid int) (model.LabelSet, error) {
	return p.labelFunc(ctx, pid)
}

func (p *StatelessProvider) Name() string {
	return p.name
}

func (p *StatelessProvider) ShouldCache() bool {
	return true
}
