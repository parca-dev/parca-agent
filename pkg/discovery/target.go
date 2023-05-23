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

package discovery

import (
	"github.com/prometheus/common/model"
)

// Group is a set of target(s) with a common label set (production, test, staging etc.).
type Group interface {
	// Source is an identifier that describes a group of targets.
	Source() string
	// Labels is a set of labels that is common across all targets in the group.
	Labels() model.LabelSet
	// NumberOfTargets returns the number of targets in the group.
	NumberOfTargets() int

	String() string
}

type SingleTargetGroup struct {
	labels model.LabelSet
	source string

	// Target entry process for this group (e.g. container or systemd unit).
	// This is used to match processes to other metadata.
	Target int
}

func (tg SingleTargetGroup) Source() string {
	return tg.source
}

func (tg SingleTargetGroup) Labels() model.LabelSet {
	return tg.labels
}

func (tg SingleTargetGroup) NumberOfTargets() int {
	return 1
}

func (tg SingleTargetGroup) String() string {
	return tg.source
}

type MultiTargetGroup struct {
	labels model.LabelSet
	source string

	// Targets is a map of PIDs identified by a label set. Each target is
	// uniquely identifiable in the group by its address label.
	Targets map[int]model.LabelSet
}

func (tg MultiTargetGroup) Source() string {
	return tg.source
}

func (tg MultiTargetGroup) Labels() model.LabelSet {
	return tg.labels
}

func (tg MultiTargetGroup) NumberOfTargets() int {
	return len(tg.Targets)
}

func (tg MultiTargetGroup) String() string {
	return tg.source
}
