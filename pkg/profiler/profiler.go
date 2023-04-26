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

package profiler

import (
	"context"

	"github.com/google/pprof/profile"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
)

// PID is the process ID of the profiling target.
// See https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.3/html_node/libc_554.html
type PID int32

// StackID consists of two parts: the first part is the process ID of the profiling target,
// the second part is the thread ID of the stack trace has been collected from.
type StackID struct {
	PID  PID
	TGID PID
}

type Location struct {
	*profile.Location

	Mapping *process.Mapping
}

func NewLocation(id, addr uint64, mapping *process.Mapping) *Location {
	// TODO(kakkoyun): Move ID logic to pprof converter.
	// - This shouldn't be a problem if we preserve the order of locations in the slice.
	return &Location{
		&profile.Location{
			ID:      id,
			Address: addr,
			Mapping: mapping.ConvertToPprof(),
		},
		mapping,
	}
}

func (l *Location) AddLine(f *Function) {
	l.Line = append(l.Line, profile.Line{Function: f.Function})
}

type Sample struct {
	*profile.Sample
}

func NewSample(locs []*Location, value int64) *Sample {
	plocs := make([]*profile.Location, 0, len(locs))
	for _, l := range locs {
		plocs = append(plocs, l.Location)
	}
	return &Sample{
		&profile.Sample{
			Value:    []int64{value},
			Location: plocs,
		},
	}
}

type Function struct {
	*profile.Function
}

func NewFunction(name string) *Function {
	return &Function{
		Function: &profile.Function{
			Name: name,
		},
	}
}

// Profile represents a capture profile of a process.
type Profile struct {
	ID StackID

	Samples   []*Sample
	Locations []*Location

	UserLocations   []*Location
	KernelLocations []*Location

	UserMappings  process.Mappings
	KernelMapping *process.Mapping

	// Only available after symbolization.
	Functions []*Function
}

type Symbolizer interface {
	Symbolize(prof *Profile) error
}

type Normalizer interface {
	Normalize(pid int, m *profile.Mapping, addr uint64) (uint64, error)
}

type ObjectFileCache interface {
	ObjectFileForProcess(pid int, m *profile.Mapping) (*objectfile.ObjectFile, error)
}

type ProcessMapCache interface {
	MappingForPID(pid int) ([]*profile.Mapping, error)
}

// TODO(kakkoyun): Change profile type to internal Profile or just a Reader (if works)!
// Any of our formats can support it.
type ProfileWriter interface {
	Write(ctx context.Context, labels model.LabelSet, prof *profile.Profile) error
}

type DebugInfoManager interface {
	EnsureUploaded(ctx context.Context, objFiles []*objectfile.ObjectFile)
}

type LabelsManager interface {
	LabelSet(name string, pid uint64) model.LabelSet
}
