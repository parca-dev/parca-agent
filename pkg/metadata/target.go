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

package metadata

import (
	"context"
	"strings"

	"github.com/prometheus/common/model"
)

// Target metadata provider.
func Target(node string, externalLabels map[string]string) Provider {
	target := targetLabels(node, externalLabels)
	return &StatelessProvider{"target", func(ctx context.Context, pid int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		labels := model.LabelSet{}
		for labelname, labelvalue := range target {
			if !strings.HasPrefix(string(labelname), "__") {
				labels[labelname] = labelvalue
			}
		}
		return labels, nil
	}}
}

func targetLabels(node string, externalLabels map[string]string) model.LabelSet {
	if externalLabels == nil {
		externalLabels = map[string]string{}
	}
	externalLabels["node"] = node

	labels := model.LabelSet{"node": model.LabelValue(node)}
	for k, v := range externalLabels {
		labels[model.LabelName(k)] = model.LabelValue(v)
	}
	return labels
}
