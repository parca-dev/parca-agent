// Copyright 2023 The Parca Authors
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

package namespace

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/parca-dev/parca-agent/pkg/cgroup"
	"github.com/prometheus/procfs"
)

type Namespace interface {
	Type() string
	Inode() uint32
}

type ns struct {
	procfs.Namespace
}

func (n ns) Type() string {
	return n.Namespace.Type
}
func (n ns) Inode() uint32 {
	return n.Namespace.Inode
}

// NamespacesForPID returns the namespaces of the process with the given PID.
func NamespacesForPID(pid int) ([]Namespace, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return nil, err
	}
	namespaces, err := proc.Namespaces()
	if err != nil {
		return nil, err
	}
	nss := make([]Namespace, len(namespaces))
	for _, namespace := range namespaces {
		nss = append(nss, ns{namespace})
	}
	return nss, nil
}

// AdjacentPIDs returns the PIDs of processes that share the same PID namespace and the same cgroup.
func AdjacentPIDs(pid int) ([]int, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return nil, err
	}
	namespaces, err := proc.Namespaces()
	if err != nil {
		return nil, err
	}
	inodes := map[uint32]struct{}{}
	for _, namespace := range namespaces {
		if namespace.Type == "pid" || namespace.Type == "pid_for_children" {
			inodes[namespace.Inode] = struct{}{}
		}
	}
	nsInodes := []uint32{}
	for inode, _ := range inodes {
		nsInodes = append(nsInodes, inode)
	}

	cgs, err := proc.Cgroups()
	if err != nil {
		return nil, err
	}
	cg := cgroup.FindContainerGroup(cgs)

	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, err
	}
	adjPIDs := map[int]struct{}{}
	for _, p := range procs {
		if p.PID == pid {
			continue
		}
		namespaces, err := p.Namespaces()
		if err != nil {
			return nil, err
		}

		cgs, err := p.Cgroups()
		if err != nil {
			return nil, err
		}
		ccg := cgroup.FindContainerGroup(cgs)

		for _, namespace := range namespaces {
			for _, inode := range nsInodes {
				if namespace.Inode == inode && ccg.Path == cg.Path {
					adjPIDs[p.PID] = struct{}{}
					break
				}
			}
		}
	}
	pids := []int{}
	for pid, _ := range adjPIDs {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

// MountNamespaceInode returns the inode of the mount namespace of the given pid.
func MountNamespaceInode(pid int) (uint64, error) {
	fileinfo, err := os.Stat(filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns/mnt"))
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}
