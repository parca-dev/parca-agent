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

package namespace

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// MountNamespaceInode returns the inode of the mount namespace of the given pid.
func MountNamespaceInode(pid int) (uint64, error) {
	fileinfo, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns/mnt"))
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

// TODO(kakkoyun): Do not expose fs.FS directly.
func FindPIDs(fs fs.FS, pid int) ([]int, error) {
	f, err := fs.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	found := false
	line := ""
	for scanner.Scan() {
		line = scanner.Text()
		if strings.HasPrefix(line, "NSpid:") {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("no NSpid line found in /proc/%d/status", pid)
	}

	return extractPIDsFromLine(line)
}

func extractPIDsFromLine(line string) ([]int, error) {
	trimmedLine := strings.TrimPrefix(line, "NSpid:")
	pidStrings := strings.Fields(trimmedLine)

	pids := make([]int, 0, len(pidStrings))
	for _, pidStr := range pidStrings {
		pid, err := strconv.ParseInt(pidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parsing pid failed on %v: %w", pidStr, err)
		}

		pids = append(pids, int(pid))
	}

	return pids, nil
}
