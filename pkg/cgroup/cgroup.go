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

package cgroup

import (
	"strings"

	"github.com/prometheus/procfs"
)

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
