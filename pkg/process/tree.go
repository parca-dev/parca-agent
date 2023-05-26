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

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/cgroup"
)

// processKey is a unique identifier for a process.
type processKey struct {
	pid int
}

type Tree struct {
	logger log.Logger

	// maxUpdateInterval is the maximum interval between full updates of the
	// process tree. This is to ensure we don't update the full process tree
	// too often.
	maxUpdateInterval time.Duration

	tree map[processKey]process
	mtx  *sync.RWMutex

	procfs procfs.FS

	fullUpdateScheduleCh chan struct{}
}

type process struct {
	proc procfs.Proc

	parent int
	// name of the field is the same as the one in kernel struct.
	starttime uint64
}

// NewTree returns a new process tree with current state of all the processes on the system.
func NewTree(
	logger log.Logger,
	procfs procfs.FS,
	maxUpdateInterval time.Duration,
) *Tree {
	return &Tree{
		logger:            logger,
		maxUpdateInterval: maxUpdateInterval,
		tree:              map[processKey]process{},
		mtx:               &sync.RWMutex{},
		procfs:            procfs,

		fullUpdateScheduleCh: make(chan struct{}, 1),
	}
}

// Run starts the process tree and update it periodically.
func (t *Tree) Run(ctx context.Context) error {
	ticker := time.NewTicker(t.maxUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// With this ticker we ensure we only update the process tree at
			// most once per updateInterval, but also only when a full update
			// is requested, which only happens when we detect a process PID
			// has been reused. So full updates are only triggered when lots of
			// short-lived processes are created constantly.

			select {
			case <-ctx.Done():
				return nil
			case <-t.fullUpdateScheduleCh:
				t.fullUpdate()
			}
		}
	}
}

func (t *Tree) scheduleFullUpdate() {
	select {
	case t.fullUpdateScheduleCh <- struct{}{}:
	default:
		// Full update is already scheduled and hasn't started executing yet,
		// so we don't need to schedule it again. This is to aviod a thundering
		// herd problem, and combined with the ticker in Run() ensures we only
		// update the full process tree at most once per updateInterval.
	}
}

// fullUpdate fully updates the process tree of known PIDs. It cleans up the
// terminated processes and updates according to potentially reused PIDs.
func (t *Tree) fullUpdate() {
	t.mtx.RLock()
	keys := make([]processKey, 0, len(t.tree))
	for processKey := range t.tree {
		keys = append(keys, processKey)
	}
	t.mtx.RUnlock()

	// Update the process tree.
	newTree, err := t.updateTree(keys)
	if err != nil {
		level.Error(t.logger).Log("msg", "failed to update the process tree", "err", err)
	}

	t.mtx.Lock()
	t.tree = newTree
	t.mtx.Unlock()
}

// Get returns the process with the given PID if it exists in the process tree.
func (t *Tree) get(k processKey) (process, bool) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	p, ok := t.tree[k]
	return p, ok
}

// FindAllAncestorProcessIDsInSameCgroup returns all ancestor process IDs for a given PID in the same cgroup.
func (t *Tree) FindAllAncestorProcessIDsInSameCgroup(pid int) ([]int, error) {
	// Fast path. Find the process if it exists in the process tree.
	if p, ok := t.get(processKey{pid: pid}); ok {
		// TODO: If we added the starttime to the key of the stacks retrieved,
		// then we could avoid these extra checks.

		// Process could have been already terminated.
		// And this could be a problem if we haven't updated the process tree yet.
		proc, err := t.readProcess(pid)
		if err != nil {
			return nil, err
		}
		if p.starttime == proc.starttime {
			return findAncestorPIDsInSameCgroup(p.proc, t.ancestorsFromCache(p))
		}

		// Same PID but different start time. PID has been reused. We make sure
		// we schedule a full update of the process tree, but continue with the
		// slow path to answer this query.
		t.scheduleFullUpdate()
	}

	// Slow path. We either have never seen this PID before or the PID has been
	// reused. Find the process by traversing the process tree by actually
	// reading the procfs. What we find will be added to the cache.
	p, err := t.readProcess(pid)
	if err != nil {
		return nil, err
	}

	ancestors, err := t.readAncestors(p)
	if err != nil {
		return nil, err
	}

	return findAncestorPIDsInSameCgroup(p.proc, ancestors)
}

func (t *Tree) readProcess(pid int) (process, error) {
	proc, err := t.procfs.Proc(pid)
	if err != nil {
		return process{}, err
	}
	stat, err := proc.Stat()
	if err != nil {
		return process{}, err
	}

	return process{
		proc:      proc,
		parent:    stat.PPID,
		starttime: stat.Starttime,
	}, nil
}

func (t *Tree) readAncestors(p process) ([]procfs.Proc, error) {
	var (
		ancestors []process
		next      = p.parent
	)

	for {
		if next == 0 {
			break
		}

		p, err := t.readProcess(next)
		if err != nil {
			return nil, err
		}

		ancestors = append(ancestors, p)
		next = p.parent
	}

	t.mtx.Lock()
	t.tree[processKey{pid: p.proc.PID}] = p
	for _, ancestor := range ancestors {
		t.tree[processKey{pid: ancestor.proc.PID}] = ancestor
	}
	t.mtx.Unlock()

	res := make([]procfs.Proc, len(ancestors))
	for i := range ancestors {
		res[i] = ancestors[i].proc
	}

	return res, nil
}

// updateTree updates the process tree with the current state of the previously
// known processes. This has two purposes:
//  1. Remove processes that have been terminated.
//  2. Update the tree in case PIDs have been reused. The best thing we can do
//     is to start over, but we try to rebuild the tree to be as close to what
//     was previously known.
//  3. Since a new map is created this also has the function that it compacts
//     the map size.
func (t *Tree) updateTree(previouslyKnownProcesses []processKey) (map[processKey]process, error) {
	newTree := map[processKey]process{}
	for _, pk := range previouslyKnownProcesses {
		proc, err := t.procfs.Proc(pk.pid)
		if err != nil {
			// Process no longer exists.
			continue
		}
		stat, err := proc.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to get process stat for PID %d: %w", proc.PID, err)
		}

		newTree[pk] = process{
			proc:      proc,
			parent:    stat.PPID,
			starttime: stat.Starttime,
		}
	}

	return newTree, nil
}

func (t *Tree) ancestorsFromCache(p process) []procfs.Proc {
	ancestors := []procfs.Proc{}
	proc := p
	for {
		if proc.parent == 0 {
			break
		}
		parent, ok := t.get(processKey{pid: proc.parent})
		if !ok {
			break
		}
		ancestors = append(ancestors, parent.proc)
		proc = parent
	}
	return ancestors
}

func findAncestorPIDsInSameCgroup(p procfs.Proc, ancestors []procfs.Proc) ([]int, error) {
	cgs, err := p.Cgroups()
	if err != nil {
		return nil, err
	}
	cg := cgroup.FindContainerGroup(cgs)

	pids := []int{}
	for _, ancestor := range ancestors {
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
