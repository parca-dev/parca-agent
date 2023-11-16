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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
)

type runtimeProvider struct {
	runtimes []Provider
}

func (p *runtimeProvider) Labels(ctx context.Context, pid int) (model.LabelSet, error) {
	allLabels := model.LabelSet{}
	var errs error
	for _, runtime := range p.runtimes {
		lset, err := runtime.Labels(ctx, pid)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		if lset != nil {
			allLabels = allLabels.Merge(lset)
		}
	}
	return allLabels, errs
}

func (p *runtimeProvider) Name() string {
	return "runtime"
}

func (p *runtimeProvider) ShouldCache() bool {
	// NOTICE: Underlying data is also cached.
	return true
}

func Runtime(reg prometheus.Registerer, procfs procfs.FS) Provider {
	return &runtimeProvider{[]Provider{
		Python(reg, procfs),
		Ruby(reg, procfs),
		NodeJS(reg, procfs),
		// TODO(kakkoyun): Convert Java.
	}}
}
