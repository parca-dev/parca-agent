// Copyright (c) 2022 The Parca Authors
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestThing(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     string
		wantErr  bool
	}{
		{
			name:     "single cgroup path",
			contents: "0::/system.slice/systemd-journald.service\n",
			want:     "/system.slice/systemd-journald.service",
			wantErr:  false,
		},
		{
			name:     "single cgroup path without trailing newline",
			contents: "0::/system.slice/systemd-journald.service",
			want:     "/system.slice/systemd-journald.service",
			wantErr:  false,
		},
		{
			name:     "deeper cgroup path",
			contents: "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n",
			want:     "/user.slice/user-1000.slice/user@1000.service/init.scope",
			wantErr:  false,
		},
		{
			name:     "root cgroup path",
			contents: "0::/",
			want:     "/",
			wantErr:  false,
		},
		{
			name: "extract cpu controller from multiple cgroup controllers",
			contents: `11:hugetlb:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
10:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
9:blkio:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
8:net_cls,net_prio:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
7:cpuset:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
6:devices:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
5:memory:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
4:perf_event:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
3:cpu,cpuacct:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-09af509f3db677a2275723fc71bff3d9b6d19e4d404c44822f2262f700adcd4b.scope
2:freezer:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
`,
			want:    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-09af509f3db677a2275723fc71bff3d9b6d19e4d404c44822f2262f700adcd4b.scope",
			wantErr: false,
		},
		{
			name: "extract cpu controller from multiple cgroup controllers",
			contents: `11:hugetlb:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
9:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
8:blkio:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
7:net_cls,net_prio:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
6:cpuset:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
5:devices:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
4:memory:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
3:perf_event:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
2:freezer:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-a.scope
1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-09af509f3db677a2275723fc71bff3d9b6d19e4d404c44822f2262f700adcd4b.scope
`,
			want:    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1ff39434b35faeef64159d11e3f96024.slice/docker-09af509f3db677a2275723fc71bff3d9b6d19e4d404c44822f2262f700adcd4b.scope",
			wantErr: false,
		},
		{
			name:     "malformed path does not panic",
			contents: "_",
			wantErr:  true,
		},
		{
			name:     "empty path does not panic",
			contents: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCgroupFileContents(tt.contents)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
