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

package profiler

import (
	"context"

	"github.com/google/pprof/profile"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

// PID is the process ID of the profiling target.
// See https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.3/html_node/libc_554.html
type PID int

// Profile represents a capture profile of a process.
type Profile struct {
	PID PID

	Samples   []*profile.Sample
	Locations []*profile.Location

	UserLocations   []*profile.Location
	KernelLocations []*profile.Location

	UserMappings  []*profile.Mapping
	KernelMapping *profile.Mapping

	// Only available after symbolization.
	Functions []*profile.Function
}

type Symbolizer interface {
	Symbolize(prof *Profile) error
}

type Normalizer interface {
	Normalize(pid int, m *profile.Mapping, addr uint64) uint64
}

type ObjectFileCache interface {
	ObjectFileForProcess(pid int, m *profile.Mapping) (*objectfile.MappedObjectFile, error)
}

type ProcessMapCache interface {
	MappingForPID(pid int) ([]*profile.Mapping, error)
}

type ProfileWriter interface {
	Write(ctx context.Context, labels model.LabelSet, prof *profile.Profile) error
}

type DebugInfoManager interface {
	EnsureUploaded(ctx context.Context, objFiles []*objectfile.MappedObjectFile)
}

type MetadataProvider interface {
	Name() string
	Labels(pid int) (model.LabelSet, error)
}
