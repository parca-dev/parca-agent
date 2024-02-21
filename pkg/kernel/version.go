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

package kernel

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/zcalusic/sysinfo"
)

func GetRelease() (*semver.Version, error) {
	var si sysinfo.SysInfo
	si.GetSysInfo()

	shortKernelVersion := si.Kernel.Release
	splitted := strings.Split(si.Kernel.Release, "-")
	if len(splitted) > 0 {
		shortKernelVersion = splitted[0]
	}

	val, err := semver.NewVersion(shortKernelVersion)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func HasKnownBugs(version *semver.Version) bool {
	knownBadRevisions, err := semver.NewConstraint(">=5.19, <6.1")
	if err != nil {
		// This will never happen. The line above is covered in tests.
		panic(fmt.Sprintf("bad constrain, this should never happen %v", err))
	}

	return knownBadRevisions.Check(version)
}
