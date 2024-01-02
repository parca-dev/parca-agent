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
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"
)

func TestUnsupportedKernelVersions(t *testing.T) {
	name := func(version string, knownBugs bool) string {
		verb := "does not have"
		if knownBugs {
			verb = "has"
		}
		return fmt.Sprintf("%s %s known bugs", version, verb)
	}

	testcases := []struct {
		version   string
		knownBugs bool
	}{
		{
			version:   "5.18",
			knownBugs: false,
		},
		{
			version:   "5.19",
			knownBugs: true,
		},
		{
			version:   "5.19.3",
			knownBugs: true,
		},
		{
			version:   "6.0.1",
			knownBugs: true,
		},
		{
			version:   "6.1",
			knownBugs: false,
		},
	}

	for _, tt := range testcases {
		t.Run(name(tt.version, tt.knownBugs), func(t *testing.T) {
			v := semver.MustParse(tt.version)
			require.Equal(t, HasKnownBugs(v), tt.knownBugs)
		})
	}
}
