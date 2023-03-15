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
	"fmt"

	"github.com/go-kit/log"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/hsperfdata"
)

func JavaProcess(logger log.Logger) Provider {
	return &StatelessProvider{"java process", func(pid int) (model.LabelSet, error) {
		cache := hsperfdata.NewCache(logger)

		java, err := cache.IsJavaProcess(pid)
		if err != nil {
			return nil, fmt.Errorf("failed to determine if PID %d belongs to a java process: %w", pid, err)
		}

		if !java {
			return nil, nil
		}

		return model.LabelSet{
			"java": model.LabelValue(fmt.Sprintf("%t", java)),
		}, nil
	}}
}
