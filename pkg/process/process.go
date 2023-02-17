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
	"context"
	"fmt"
	"sync"
	"time"

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

type Tree struct {
	resetDuration time.Duration

	tree        map[key]*process
	mtx         *sync.RWMutex
	disappeared []key
	reused      map[key]*process
}

type process struct {
	procfs.Proc

	tree *Tree

	parent int
	// name of the field is the same as the one in kernel struct.
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
		parent, ok := p.tree.get(k)
		if !ok {
			break
		}
		ancestors = append(ancestors, &parent.Proc)
		proc = parent
	}
	return ancestors
}

// NewTree returns a new process tree with current state of all the processes on the system.
func NewTree(resetDuration time.Duration) *Tree {
	return &Tree{
		resetDuration: resetDuration,
		tree:          make(map[key]*process),
		mtx:           &sync.RWMutex{},
		disappeared:   []key{},
		reused:        make(map[key]*process),
	}
}

// Run starts the process tree.
func (t *Tree) Run(ctx context.Context) error {
	// This is a very naive pruning implementation. It will be improved in the future.
	ticker := time.NewTicker(t.resetDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			t.prune()
		}
	}
}

// Even though, the whole prune method is not goroutine-safe, it is only used by Run method.
// So there is only one goroutine that can access it at once.
func (t *Tree) prune() {
	// Prune disappeared processes.
	if len(t.disappeared) > 0 {
		t.mtx.Lock()
		for _, k := range t.disappeared {
			delete(t.tree, k)
		}
		t.mtx.Unlock()
		t.disappeared = []key{}
	}

	keys := make([]key, 0, len(t.tree))
	t.mtx.RLock()
	for k := range t.tree {
		keys = append(keys, k)
	}
	t.mtx.RUnlock()

	for _, k := range keys {
		proc, err := procfs.NewProc(k.pid)
		if err != nil {
			// Will be pruned in the next iteration.
			t.disappeared = append(t.disappeared, k)
			continue
		}
		stat, err := proc.Stat()
		if err != nil {
			// Will be pruned in the next iteration.
			t.disappeared = append(t.disappeared, k)
			continue
		}
		// It is possible that the process has been reused. Update the process.
		p, ok := t.get(k)
		if !ok {
			continue
		}
		if p.starttime != stat.Starttime {
			t.reused[k] = &process{
				Proc:      proc,
				tree:      t,
				parent:    stat.PPID,
				starttime: stat.Starttime,
			}
		}
	}

	// Update the process tree.
	if len(t.reused) > 0 {
		t.mtx.Lock()
		for k, p := range t.reused {
			t.tree[k] = p
		}
		t.mtx.Unlock()
		t.reused = make(map[key]*process)
	}
}

// Get returns the process with the given PID if it exists in the process tree.
func (t *Tree) Get(pid int) (*procfs.Proc, bool) {
	if p, ok := t.get(key{pid: pid}); ok {
		return &p.Proc, true
	}
	return nil, false
}

func (t *Tree) get(k key) (*process, bool) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	p, ok := t.tree[k]
	if !ok {
		return nil, false
	}
	return p, true
}

func (t *Tree) update(k key, p *process) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	t.tree[k] = p
}

func (t *Tree) delete(k key) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	delete(t.tree, k)
}

// FindAllAncestorProcessIDsInSameCgroup returns all ancestor process IDs for a given PID in the same cgroup.
func (t *Tree) FindAllAncestorProcessIDsInSameCgroup(pid int) ([]int, error) {
	// Fast path. Find the process if it exists in the process tree.
	k := key{pid: pid}
	if p, ok := t.get(k); ok {
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
	if err := t.populate(); err != nil {
		return nil, fmt.Errorf("failed to populate process tree: %w", err)
	}

	// Tree is updated. Try to find the process again.
	p, ok := t.get(k)
	if !ok {
		return nil, fmt.Errorf("failed to find the process for PID %d", pid)
	}
	return findAncestorPIDsInSameCgroup(p)
}

func (t *Tree) populate() error {
	procs, err := procfs.AllProcs()
	if err != nil {
		return fmt.Errorf("failed to get all processes: %w", err)
	}

	for _, p := range procs {
		k := key{pid: p.PID}
		if _, ok := t.get(k); ok {
			continue
		}

		proc, err := procfs.NewProc(p.PID)
		if err != nil {
			return fmt.Errorf("failed to get process for PID %d: %w", p.PID, err)
		}
		stat, err := proc.Stat()
		if err != nil {
			return fmt.Errorf("failed to get process stat for PID %d: %w", p.PID, err)
		}
		t.update(k, &process{
			Proc:      p,
			tree:      t,
			parent:    stat.PPID,
			starttime: stat.Starttime,
		})
	}
	return nil
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
