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

package rlimit

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dustin/go-humanize"
	"golang.org/x/sys/unix"
)

var rlimitMu sync.Mutex

// BumpMemlock increases the current memlock limit to a value more reasonable for the profiler's needs.
func BumpMemlock(cur, max uint64) (syscall.Rlimit, error) {
	rLimit := syscall.Rlimit{
		Cur: cur, // Soft limit.
		Max: max, // Hard limit (ceiling for rlim_cur).
	}

	if cur == 0 && max == 0 {
		// RemoveMemlock removes the limit on the amount of memory the current process can lock into RAM, if necessary.
		// This is not required to load eBPF resources on kernel versions 5.11+ due to the introduction of cgroup-based memory accounting.
		//  On such kernels the function is a no-op.
		// Since the function may change global per-process limits it should be invoked at program start up, in main() or init().
		// This function exists as a convenience and should only be used when permanently raising RLIMIT_MEMLOCK to infinite is appropriate.
		// Consider invoking prlimit(2) directly with a more reasonable limit if desired.
		// Requires CAP_SYS_RESOURCE on kernels < 5.11.
		if err := rlimit.RemoveMemlock(); err != nil {
			return rLimit, fmt.Errorf("failed to remove memlock rlimit: %w", err)
		}
	} else {
		rlimitMu.Lock()
		// RLIMIT_MEMLOCK is 0x8.
		if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
			rlimitMu.Unlock()
			return rLimit, fmt.Errorf("failed to increase rlimit: %w", err)
		}
		rlimitMu.Unlock()
	}

	rLimit = syscall.Rlimit{}
	if err := syscall.Getrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		return rLimit, fmt.Errorf("failed to get rlimit: %w", err)
	}

	return rLimit, nil
}

func HumanizeRLimit(val uint64) string {
	if val == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return humanize.Bytes(val)
}

// Files returns the currently opened file descriptors as well
// as the maximum number of file descriptors that can be
// opened by the calling process.
func Files() (int, int, error) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0, 0, err
	}
	// From the manpage:
	// > This specifies a value one greater than the maximum file
	// > descriptor number that can be opened by this process.
	return int(limit.Cur), int(limit.Max) - 1, nil
}
