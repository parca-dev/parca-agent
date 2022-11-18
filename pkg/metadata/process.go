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
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
)

func Process() Provider {
	return &StatelessProvider{"process", func(pid int) (model.LabelSet, error) {
		p, err := procfs.NewProc(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate procfs for PID %d: %w", pid, err)
		}

		cgroups, err := p.Cgroups()
		if err != nil {
			return nil, fmt.Errorf("failed to get cgroups for PID %d: %w", pid, err)
		}

		cgroup := findCPUCgroup(cgroups)

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

func findCPUCgroup(cgroups []procfs.Cgroup) procfs.Cgroup {
	if len(cgroups) == 1 {
		return cgroups[0]
	} else {
		for _, cg := range cgroups {
			for _, ctlr := range cg.Controllers {
				if ctlr == "cpu" {
					return cg
				}
			}

			if strings.Contains(cg.Path, "systemd") {
				return cg
			}

			for _, ctlr := range cg.Controllers {
				if strings.Contains(ctlr, "systemd") {
					return cg
				}
			}
		}
	}

	return procfs.Cgroup{}
}
