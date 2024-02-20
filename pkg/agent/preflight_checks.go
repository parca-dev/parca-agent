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

package agent

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-kit/log"
	"github.com/parca-dev/parca-agent/pkg/contained"
	"github.com/parca-dev/parca-agent/pkg/kernel"
)

// PreflightChecks checks if the agent is ready to start.
func PreflightChecks(
	allowRunningAsNonRoot bool,
	allowRunningInNonRootPIDNamespace bool,
	ignoreUnsafeKernelVersion bool,
) (bool, error) {
	var errs error
	isRootPIDNamespace, err := contained.IsRootPIDNamespace(log.NewNopLogger())
	if !isRoot() && !allowRunningAsNonRoot {
		return false, errors.New("superuser (root) is required to run Parca Agent to load and manipulate BPF programs")
	}
	if err == nil {
		if !isRootPIDNamespace && !allowRunningInNonRootPIDNamespace {
			return false, errors.New(
				"the agent can't run in a container, run with privileges and in the host PID (`hostPID: true` in Kubernetes, `--pid host` in Docker)",
			)
		}
	} else {
		errs = errors.Join(errs, errors.New("failed to determine if the agent is running in a container"))
	}

	release, err := kernel.GetRelease()
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to determine the kernel version, error: %w", err))
	} else if kernel.HasKnownBugs(release) && !ignoreUnsafeKernelVersion {
		return false, errors.New("this kernel version might cause issues such as freezing your system (https://github.com/parca-dev/parca-agent/discussions/2071). This can be bypassed with --ignore-unsafe-kernel-version but bad things can happen")
	}

	if err := kernel.CheckBPFEnabled(); err != nil {
		// TODO: Add a more definitive test for the cases kconfig fails.
		// - https://github.com/libbpf/libbpf/blob/1714037104da56308ddb539ae0a362a9936121ff/src/libbpf.c#L4396-L4429
		errs = errors.Join(errs, fmt.Errorf("failed to determine if eBPF is supported, host kernel might not support eBPF, error: %w", err))
	}

	return true, errs
}

func isRoot() bool {
	return os.Geteuid() == 0
}
