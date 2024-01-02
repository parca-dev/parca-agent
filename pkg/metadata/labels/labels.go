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

package labels

import (
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

const profilerName = "__name__"

func ProfilerName(name string) labels.Label {
	return labels.Label{
		Name:  profilerName,
		Value: name,
	}
}

func WithProfilerName(ls model.LabelSet, name string) model.LabelSet {
	return ls.Merge(model.LabelSet{
		profilerName: model.LabelValue(name),
	})
}
