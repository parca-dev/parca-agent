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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

func Python(procfs procfs.FS, reg prometheus.Registerer, objFilePool *objectfile.Pool) Provider {
	cache := cache.NewLRUCache[string, bool](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "metadata_python"}, reg),
		512,
	)
	return &StatelessProvider{"python", func(ctx context.Context, pid int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		p, err := procfs.Proc(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate procfs for PID %d: %w", pid, err)
		}

		executable, err := p.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable for PID %d: %w", pid, err)
		}

		if python, ok := cache.Get(executable); ok {
			if !python {
				return nil, nil
			}
			return model.LabelSet{
				"python": model.LabelValue(fmt.Sprintf("%t", true)),
			}, nil
		}

		comm, err := p.Comm()
		if err != nil {
			return nil, fmt.Errorf("failed to get comm for PID %d: %w", pid, err)
		}

		if strings.HasPrefix(comm, "python") {
			cache.Add(executable, true)
			return model.LabelSet{
				"python": model.LabelValue(fmt.Sprintf("%t", true)),
			}, nil
		}

		obj, err := objFilePool.Open(executable)
		if err != nil {
			return nil, fmt.Errorf("failed to open ELF file for process %d: %w", pid, err)
		}

		ef, release, err := obj.ELF()
		if err != nil {
			return nil, fmt.Errorf("failed to get ELF file for process %d: %w", pid, err)
		}
		defer release()

		python, err := runtime.IsPython(ef)
		if err != nil {
			return nil, fmt.Errorf("failed to determine if PID %d belongs to a python process: %w", pid, err)
		}

		cache.Add(executable, python)
		if !python {
			return nil, nil
		}
		return model.LabelSet{
			"python": model.LabelValue(fmt.Sprintf("%t", true)),
		}, nil
	}}
}
