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
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/vm"
)

func Runtime(procfs procfs.FS, reg prometheus.Registerer) Provider {
	cache := cache.NewLRUCache[int, *runtime.Runtime](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "metadata_runtime"}, reg),
		512,
	)
	return &StatelessProvider{"runtime", func(ctx context.Context, pid int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		p, err := procfs.Proc(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate procfs for PID %d: %w", pid, err)
		}

		if rt, ok := cache.Get(pid); ok {
			if rt == nil {
				return nil, nil
			}
			return model.LabelSet{
				"runtime":         model.LabelValue(rt.Type),
				"runtime_version": model.LabelValue(rt.Version.String()),
			}, nil
		}

		rt, err := vm.Fetch(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch interpreter info for PID %d: %w", pid, err)
		}
		if rt == nil {
			cache.Add(pid, nil)
			return nil, nil
		}
		cache.Add(pid, rt)

		return model.LabelSet{
			"runtime":         model.LabelValue(rt.Type),
			"runtime_version": model.LabelValue(rt.Version.String()),
		}, nil
	}}
}
