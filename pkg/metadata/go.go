// Copyright (c) 2022 The Parca Authors
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
	"github.com/google/gops/goprocess"
	"github.com/prometheus/common/model"
)

func Go() *Provider {
	return &Provider{
		"go", func(pid int) (model.LabelSet, error) {
			md := map[int]model.LabelSet{}
			for _, ps := range goprocess.FindAll() {
				md[ps.PID] = model.LabelSet{
					"build_version": model.LabelValue(ps.BuildVersion),
					"executable":    model.LabelValue(ps.Exec),
				}
			}
			return md[pid], nil
		},
	}
}
