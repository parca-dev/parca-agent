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
	"fmt"
	"strconv"

	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/cgroup"
)

func Process(procfs procfs.FS) Provider {
	return &StatelessProvider{"process", func(ctx context.Context, pid int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		p, err := procfs.Proc(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate procfs for PID %d: %w", pid, err)
		}

		cgroups, err := p.Cgroups()
		if err != nil {
			return nil, fmt.Errorf("failed to get cgroups for PID %d: %w", pid, err)
		}

		cgroup := cgroup.FindContainerGroup(cgroups)

		comm, err := p.Comm()
		if err != nil {
			return nil, fmt.Errorf("failed to get comm for PID %d: %w", pid, err)
		}

		executable, err := p.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable for PID %d: %w", pid, err)
		}

		stat, err := p.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to get stat for PID %d: %w", pid, err)
		}

		return model.LabelSet{
			"cgroup_name": model.LabelValue(cgroup.Path),
			"comm":        model.LabelValue(comm),
			"executable":  model.LabelValue(executable),
			"ppid":        model.LabelValue(strconv.Itoa(stat.PPID)),
		}, nil
	}}
}
