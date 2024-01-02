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
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/prometheus/procfs"
)

/*
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

struct cgid_file_handle
{
  //struct file_handle handle;
  unsigned int handle_bytes;
  int handle_type;
  uint64_t cgid;
};

uint64_t get_cgroupid(char *path) {
  struct cgid_file_handle *h;
  int mount_id;
  int err;
  uint64_t ret;

  h = malloc(sizeof(struct cgid_file_handle));
  if (!h)
    return 0;

  h->handle_bytes = 8;
  err = name_to_handle_at(AT_FDCWD, path, (struct file_handle *)h, &mount_id, 0);
  if (err != 0) {
    free(h);
    return 0;
  }

  if (h->handle_bytes != 8) {
    free(h);
    return 0;
  }

  ret = h->cgid;
  free(h);

  return ret;
}
*/
import "C"

// FindContainerGroup returns the cgroup with the cpu controller or first systemd slice cgroup.
func FindContainerGroup(cgroups []procfs.Cgroup) procfs.Cgroup {
	// If only 1 cgroup, simply return it
	if len(cgroups) == 1 {
		return cgroups[0]
	}

	for _, cg := range cgroups {
		// Find first cgroup v1 with cpu controller
		for _, ctlr := range cg.Controllers {
			if ctlr == "cpu" {
				return cg
			}
		}

		// Find first systemd slice
		// https://systemd.io/CGROUP_DELEGATION/#systemds-unit-types
		if strings.HasPrefix(cg.Path, "/system.slice/") || strings.HasPrefix(cg.Path, "/user.slice/") {
			return cg
		}

		// FIXME: what are we looking for here?
		// https://systemd.io/CGROUP_DELEGATION/#controller-support
		for _, ctlr := range cg.Controllers {
			if strings.Contains(ctlr, "systemd") {
				return cg
			}
		}
	}

	return procfs.Cgroup{}
}

// PathV2AddMountpoint adds the cgroup2 mountpoint to a path.
func PathV2AddMountpoint(path string) (string, error) {
	pathWithMountpoint := filepath.Join("/sys/fs/cgroup/unified", path)
	if _, err := os.Stat(pathWithMountpoint); os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
		pathWithMountpoint = filepath.Join("/sys/fs/cgroup", path)
		if _, err := os.Stat(pathWithMountpoint); os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("cannot access cgroup %q: %w", path, err)
		}
	}
	return pathWithMountpoint, nil
}

// ID returns the cgroup2 ID of a path.
func ID(pathWithMountpoint string) (uint64, error) {
	cPathWithMountpoint := C.CString(pathWithMountpoint)
	ret := uint64(C.get_cgroupid(cPathWithMountpoint))
	C.free(unsafe.Pointer(cPathWithMountpoint))
	if ret == 0 {
		return 0, fmt.Errorf("GetCgroupID on %q failed", pathWithMountpoint)
	}
	return ret, nil
}

// Paths returns the cgroup1 and cgroup2 paths of a process.
// It does not include the "/sys/fs/cgroup/{unified,systemd,}" prefix.
func Paths(pid int) (string, string, error) {
	cgroupPathV1 := ""
	cgroupPathV2 := ""
	if cgroupFile, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cgroup")); err == nil {
		defer cgroupFile.Close()

		reader := bufio.NewReader(cgroupFile)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			// Fallback in case the system the agent is running on doesn't run systemd
			if strings.Contains(line, ":perf_event:") {
				cgroupPathV1 = strings.SplitN(line, ":", 3)[2]
				cgroupPathV1 = strings.TrimSuffix(cgroupPathV1, "\n")
				continue
			}
			if strings.HasPrefix(line, "1:name=systemd:") {
				cgroupPathV1 = strings.TrimPrefix(line, "1:name=systemd:")
				cgroupPathV1 = strings.TrimSuffix(cgroupPathV1, "\n")
				continue
			}
			if strings.HasPrefix(line, "0::") {
				cgroupPathV2 = strings.TrimPrefix(line, "0::")
				cgroupPathV2 = strings.TrimSuffix(cgroupPathV2, "\n")
				continue
			}
		}
	} else {
		return "", "", fmt.Errorf("cannot parse cgroup: %w", err)
	}

	if cgroupPathV1 == "/" {
		cgroupPathV1 = ""
	}

	if cgroupPathV2 == "/" {
		cgroupPathV2 = ""
	}

	if cgroupPathV2 == "" && cgroupPathV1 == "" {
		return "", "", fmt.Errorf("cannot find cgroup path in /proc/PID/cgroup")
	}

	return cgroupPathV1, cgroupPathV2, nil
}
