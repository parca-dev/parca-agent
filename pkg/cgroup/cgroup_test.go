// Copyright 2022-2024 The Parca Authors
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

package cgroup

import (
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
)

func TestFindFirstCPUCgroup(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		cgroups   []procfs.Cgroup
		wantIndex int
	}{
		{
			name: "single cgroup path",
			cgroups: []procfs.Cgroup{{
				HierarchyID: 0,
				Controllers: []string{},
				Path:        "/system.slice/systemd-journald.service",
			}},
			wantIndex: 0,
		},
		{
			name: "single cgroup path without trailing newline",
			cgroups: []procfs.Cgroup{{
				HierarchyID: 0,
				Controllers: []string{},
				Path:        "/system.slice/systemd-journald.service",
			}},
			wantIndex: 0,
		},
		{
			name: "deeper cgroup path",
			cgroups: []procfs.Cgroup{{
				HierarchyID: 0,
				Controllers: []string{},
				Path:        "/user.slice/user-1000.slice/user@1000.service/init.scope",
			}},
			wantIndex: 0,
		},
		{
			name: "root cgroup path",
			cgroups: []procfs.Cgroup{{
				HierarchyID: 0,
				Controllers: []string{},
				Path:        "/",
			}},
			wantIndex: 0,
		},
		{
			name: "extract cpu controller from multiple cgroup controllers",
			cgroups: []procfs.Cgroup{
				{
					HierarchyID: 11,
					Controllers: []string{"hugetlb"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 10,
					Controllers: []string{"pids"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 9,
					Controllers: []string{"blkio"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 8,
					Controllers: []string{"net_cls", "net_prio"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 7,
					Controllers: []string{"cpuset"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 6,
					Controllers: []string{"devices"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 5,
					Controllers: []string{"memory"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 4,
					Controllers: []string{"perf_event"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 3,
					Controllers: []string{"cpu", "cpuacct"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-09af509f3db677a2275723fc71bff3d9b6d19e4d404c44822f2262f700adcd4b.scope",
				},
				{
					HierarchyID: 2,
					Controllers: []string{"freezer"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 1,
					Controllers: []string{"name=systemd"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
			},
			wantIndex: 8,
		},
		{
			name: "extract cpu controller from multiple cgroup controllers",
			cgroups: []procfs.Cgroup{
				{
					HierarchyID: 11,
					Controllers: []string{"hugetlb"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 9,
					Controllers: []string{"pids"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 8,
					Controllers: []string{"blkio"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 7,
					Controllers: []string{"net_cls", "net_prio"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 6,
					Controllers: []string{"cpuset"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 5,
					Controllers: []string{"devices"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 4,
					Controllers: []string{"memory"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 3,
					Controllers: []string{"perf_event"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 2,
					Controllers: []string{"freezer"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope",
				},
				{
					HierarchyID: 1,
					Controllers: []string{"name=systemd"},
					Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-09af509f3db677a2275723fc71bff3d9b6d19e4d404c44822f2262f700adcd4b.scope",
				},
			},
			wantIndex: 9,
		},
		{
			name:      "empty cgroups list returns \"zero\" cgroup",
			cgroups:   []procfs.Cgroup{},
			wantIndex: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindContainerGroup(tt.cgroups)
			if tt.wantIndex < 0 {
				require.Equal(t, procfs.Cgroup{}, got)
			} else {
				require.Equal(t, tt.cgroups[tt.wantIndex], got)
			}
		})
	}
}
