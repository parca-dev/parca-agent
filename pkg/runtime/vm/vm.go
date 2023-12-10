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

package vm

import (
	"fmt"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/nodejs"
)

func Fetch(p procfs.Proc) (*runtime.Runtime, error) {
	rt, err := nodejs.RuntimeInfo(p)
	if rt == nil {
		if err != nil {
			return nil, fmt.Errorf("failed to fetch nodejs runtime info: %w", err)
		}
		// Expected case, the process is not a nodejs process.
		return nil, nil //nolint: nilnil
	}

	return rt, nil
}
