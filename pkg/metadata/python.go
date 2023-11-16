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

//nolint:dupl
package metadata

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/runtime/python"
)

func Python(reg prometheus.Registerer, procfs procfs.FS) Provider {
	cache := cache.NewLRUCache[int, model.LabelSet](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "metadata_python"}, reg),
		128,
	)
	return &StatelessProvider{"python", func(ctx context.Context, pid int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if lset, ok := cache.Get(pid); ok {
			return lset, nil
		}

		p, err := procfs.Proc(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate procfs for PID %d: %w", pid, err)
		}

		ok, err := python.IsRuntime(p)
		if err != nil {
			return nil, fmt.Errorf("failed to check if PID %d is a Python runtime: %w", pid, err)
		}
		if !ok {
			cache.Add(pid, nil)
			return nil, nil
		}
		lset := model.LabelSet{
			"python": model.LabelValue(fmt.Sprint(true)),
		}

		rt, err := python.RuntimeInfo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch interpreter info for PID %d: %w", pid, err)
		}
		if rt == nil {
			cache.Add(pid, lset)
			return nil, nil
		}

		lset = lset.Merge(model.LabelSet{
			"python_version": model.LabelValue(rt.Version.String()),
		})
		cache.Add(pid, lset)
		return lset, nil
	}}
}
