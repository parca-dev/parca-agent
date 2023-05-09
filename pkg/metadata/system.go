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

package metadata

import (
	"strings"
	"sync"
	"syscall"

	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/buildinfo"
)

var (
	labels model.LabelSet
	once   sync.Once
)

type systemProvider struct {
	StatelessProvider
}

func (p *systemProvider) ShouldCache() bool {
	// Uses its own cache.
	return false
}

// System provides metadata for the current system.
func System() Provider {
	once.Do(setMetadata)

	return &systemProvider{StatelessProvider{"system", func(_ int) (model.LabelSet, error) {
		return labels, nil
	}}}
}

// Call the system metadata getters just once as they will not
// change while the Agent is running.
func setMetadata() {
	release := "unknown"
	revision := "unknown"

	r, err := KernelRelease()
	if err == nil {
		release = r
	}

	b, err := buildinfo.FetchBuildInfo()
	if err == nil {
		revision = b.VcsRevision
	}

	labels = model.LabelSet{
		"kernel_release": model.LabelValue(release),
		"agent_revision": model.LabelValue(revision),
	}
}

func int8SliceToString(arr []int8) string {
	var b strings.Builder
	for _, v := range arr {
		// NUL byte, as it's a C string.
		if v == 0 {
			break
		}
		b.WriteByte(byte(v))
	}
	return b.String()
}

func KernelRelease() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", err
	}

	return int8SliceToString(uname.Release[:]), nil
}
