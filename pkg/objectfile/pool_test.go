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

// nolint:wastedassign,dupl
package objectfile

import (
	"testing"
)

func TestRemoveProcPrefix(t *testing.T) {
	// - (for extracted debuginfo) /tmp/<buildid>
	// - (for found debuginfo) /usr/lib/debug/.build-id/<2-char>/<buildid>.debug
	// - (for running processes) /proc/123/root/usr/bin/parca-agent
	// - (for shared libraries) /proc/123/root/usr/lib/libc.so.6
	// - (for singleton objects) /usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so
	tests := []struct {
		name     string
		path     string
		wantPath string
	}{
		{
			name:     "remove /proc/<pid>/root prefix",
			path:     "/proc/123/root/exe",
			wantPath: "/exe",
		},
		{
			name:     "kepp /proc/<pid>/ prefix",
			path:     "/proc/1234/cwd",
			wantPath: "/proc/1234/cwd",
		},
		{
			name:     "keep path intact if no match",
			path:     "/bin/bash",
			wantPath: "/bin/bash",
		},
		{
			name:     "shared libraries",
			path:     "/proc/123/root/usr/lib/libc.so.6",
			wantPath: "/usr/lib/libc.so.6",
		},
		{
			name:     "extracted debuginfo",
			path:     "/tmp/1234",
			wantPath: "/tmp/1234",
		},
		{
			name:     "found debuginfo",
			path:     "/usr/lib/debug/.build-id/12/1234.debug",
			wantPath: "/usr/lib/debug/.build-id/12/1234.debug",
		},
		{
			name:     "singleton objects",
			path:     "/usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so",
			wantPath: "/usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath := removeProcPrefix(tt.path)
			if gotPath != tt.wantPath {
				t.Errorf("removeProcPrefix() = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}
