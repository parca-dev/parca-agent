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

package hsperfdata

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/go-kit/log"

	"golang.org/x/sync/singleflight"

	"github.com/parca-dev/parca-agent/pkg/perf"
)

const hsperfdata = "/tmp/hsperfdata_*"

type Cache struct {
	pids   map[int]struct{}
	fs     fs.FS
	logger log.Logger
	mu     sync.Mutex
	nsPID  map[int]int
	group  singleflight.Group
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func NewCache(logger log.Logger) *Cache {
	return &Cache{
		pids:   make(map[int]struct{}),
		fs:     &realfs{},
		logger: logger,
		nsPID:  map[int]int{},
	}
}

func (c *Cache) Exists(pid int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.pids[pid]
	return ok
}

// IsJavaProcess returns true if the hsperfdata file exists for a given pid.
// It first searches in all hsperfdata user directories for the processes
// running on host and then searches in /proc/{pid}/root/tmp for processes
// running in containers. Note that pids are assumed to be unique regardless
// of username.
func (c *Cache) IsJavaProcess(pid int) (bool, error) {
	// Check if the pid is in the cache.
	if c.Exists(pid) {
		return true, nil
	}

	// Use singleflight to prevent concurrent requests for the same pid
	ch := c.group.DoChan(strconv.Itoa(pid), func() (interface{}, error) {
		// Fast path to find the processes running on the host.
		// List all directories that match the pattern /tmp/hsperfdata_*
		dirs, err := filepath.Glob(hsperfdata)
		if err != nil {
			return false, fmt.Errorf("failed to list directories: %w", err)
		}

		// Loop over all directories and search for the hsperfdata file for the given pid
		for _, dir := range dirs {
			hsperfdataPath := filepath.Join(dir, strconv.Itoa(pid))
			if path, err := c.fs.Open(hsperfdataPath); err == nil {
				defer path.Close()
				c.pids[pid] = struct{}{}
				return true, nil
			}
		}

		// Slow path for the processes running in containers.
		// Search for the pid via nspids.
		nsPid, found := c.nsPID[pid]
		if !found {
			nsPids, err := perf.FindNSPIDs(c.fs, pid)
			if err != nil {
				if os.IsNotExist(err) {
					return false, fmt.Errorf("%w when reading status", perf.ErrProcNotFound)
				}
				return false, err
			}
			// If we didn't find the pid in the root PID namespace, try to find it in the
			// namespaces of the process. Store the namespace PID in the nsPID map to
			// avoid searching for it again in the future.
			// Note that the PID of the root PID namespace will always be the last element
			// in the slice returned by perf.FindNSPIDs.
			c.nsPID[pid] = nsPids[len(nsPids)-1]
			nsPid = c.nsPID[pid]
		}

		// TODO(vthakkar): Check for the process mount point.
		perfdataFiles := fmt.Sprintf("/proc/%d/root/tmp/", pid)

		files, err := os.ReadDir(perfdataFiles)
		if err != nil {
			return false, fmt.Errorf("error reading %s: %w", perfdataFiles, err)
		}

		for _, f := range files {
			if f.IsDir() {
				if name := f.Name(); strings.HasPrefix(name, "hsperfdata") {
					if path, err := c.fs.Open(filepath.Join(perfdataFiles, name, strconv.Itoa(nsPid))); err == nil {
						defer path.Close()
						c.pids[pid] = struct{}{}
						return true, nil
					}
				}
			}
		}
		return false, nil
	})

	result := <-ch
	if result.Err != nil {
		return false, result.Err
	}

	val, ok := result.Val.(bool)
	if !ok {
		return false, fmt.Errorf("failed to convert the result to bool")
	}

	return val, nil
}
