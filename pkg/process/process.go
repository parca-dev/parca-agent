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

// key is a unique identifier for a process.
// TODO(kakkoyun): This is not unique enough. We will need to add more fields.
// For example, we can use the process start time to make sure we are not.
// However, reading the stats file is expensive. For now, we will rely on the PID.
// I will keep the struct to make it easier to add more fields in the future.
type key struct {
	pid int
}

type psTree map[key]*process

type process struct {
	procfs.Proc

	tree *psTree

	parent    int
	starttime uint64
}

func (p *process) ancestors() []*procfs.Proc {
	ancestors := []*procfs.Proc{}
	proc := p
	for {
		if proc.parent == 0 {
			break
		}
		k := key{pid: proc.parent}
		parent, ok := (*p.tree)[k]
		if !ok {
			break
		}
		ancestors = append(ancestors, &parent.Proc)
		proc = parent
	}
	return ancestors
}

// TODO(kakkoyun): This is an ever growing map. Introduce a mechanism to prune it.
var tree psTree = map[key]*process{}

// FindAllAncestorProcessIDsInSameCgroup returns all ancestor process IDs for a given PID in the same cgroup.
func FindAllAncestorProcessIDsInSameCgroup(pid int) ([]int, error) {
	// Fast path. Find the process if it exists in the process tree.
	k := key{pid: pid}
	if p, ok := tree[k]; ok {
		// Process could have been already terminated.
		// And this could be a problem if we haven't updated the process tree yet.
		proc, err := procfs.NewProc(pid)
		if err != nil {
			return nil, err
		}
		stat, err := proc.Stat()
		if err != nil {
			return nil, err
		}
		if p.starttime == stat.Starttime {
			return findAncestorPIDsInSameCgroup(p)
		}
		// Same PID but different start time. PID has been reused.
	}

	// Update the process tree.
	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, fmt.Errorf("failed to get all processes: %w", err)
	}
	for _, p := range procs {
		k := key{pid: p.PID}
		if _, ok := tree[k]; ok {
			continue
		}

		proc, err := procfs.NewProc(p.PID)
		if err != nil {
			return nil, err
		}
		stat, err := proc.Stat()
		if err != nil {
			return nil, err
		}
		tree[k] = &process{
			Proc:      p,
			tree:      &tree,
			parent:    stat.PPID,
			starttime: stat.Starttime,
		}
	}

	// Tree is updated. Try to find the process again.
	p, ok := tree[k]
	if !ok {
		return nil, fmt.Errorf("failed to get process for PID %d: %w", pid, err)
	}
	return findAncestorPIDsInSameCgroup(p)
}

// TODO(kakkoyun): The result of this function can be cached if needed.
func findAncestorPIDsInSameCgroup(p *process) ([]int, error) {
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
