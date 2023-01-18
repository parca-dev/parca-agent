// Copyright 2022 The Parca Authors
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

package buildinfo

import (
	"errors"
	"runtime/debug"
)

type buildInfo struct {
	GoArch, GoOs, VcsRevision, VcsTime string
	VcsModified                        bool
}

func FetchBuildInfo() (*buildInfo, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, errors.New("can't read the build info")
	}

	buildInfo := buildInfo{}

	for _, setting := range bi.Settings {
		key := setting.Key
		value := setting.Value

		switch key {
		case "GOARCH":
			buildInfo.GoArch = value
		case "GOOS":
			buildInfo.GoOs = value
		case "vcs.revision":
			buildInfo.VcsRevision = value
		case "vcs.time":
			buildInfo.VcsTime = value
		case "vcs.modified":
			buildInfo.VcsModified = value == "true"
		}
	}

	return &buildInfo, nil
}
