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

package process

import (
	"fmt"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/cgroup"
)

type psTree map[int]*process

type process struct {
	procfs.Proc

	tree   *psTree
	parent int
}

func (p *process) ancestors() []*procfs.Proc {
	ancestors := []*procfs.Proc{}
	proc := p
	for {
		if proc.parent == 0 {
			break
		}
		parent, ok := (*p.tree)[proc.parent]
		if !ok {
			break
		}
		ancestors = append(ancestors, &parent.Proc)
		proc = parent
	}
	return ancestors
}

var tree psTree = map[int]*process{}

// FindAllAncestorProcessIDs returns all ancestor process IDs for a given PID.
func FindAllAncestorProcessIDs(pid int) ([]int, error) {
	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, fmt.Errorf("failed to get all processes: %w", err)
	}

	for _, p := range procs {
		if _, ok := tree[p.PID]; ok {
			continue
		}
		stat, err := p.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to get stat for PID %d: %w", p.PID, err)
		}
		tree[p.PID] = &process{
			Proc:   p,
			tree:   &tree,
			parent: stat.PPID,
		}
	}

	p, ok := tree[pid]
	if !ok {
		return nil, fmt.Errorf("failed to get process for PID %d: %w", pid, err)
	}

	proc := p.Proc
	cgs, err := proc.Cgroups()
	if err != nil {
		return nil, err
	}
	cg := cgroup.FindContainerGroup(cgs)

	pids := []int{}
	for _, ancestor := range p.ancestors() {
		cgs, err := ancestor.Cgroups()
		if err != nil {
			return nil, err
		}
		ccg := cgroup.FindContainerGroup(cgs)
		if ccg.Path == cg.Path {
			pids = append(pids, ancestor.PID)
		}
	}
	return pids, nil
}
