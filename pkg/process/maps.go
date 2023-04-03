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

package process

import (
	"github.com/google/pprof/profile"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type MapManager struct {
	*procfs.FS
}

func NewMapManager(fs procfs.FS) *MapManager {
	return &MapManager{&fs}
}

type Mappings []*Mapping

func (ms Mappings) ConvertToPprof() []*profile.Mapping {
	res := make([]*profile.Mapping, 0, len(ms))
	for _, m := range ms {
		res = append(res, m.ConvertToPprof())
	}
	return res
}

type Mapping struct {
	*procfs.ProcMap

	id      int
	objFile *objectfile.MappedObjectFile

	pprof *profile.Mapping
}

func (m *Mapping) ConvertToPprof() *profile.Mapping {
	if m.objFile == nil {
		// TODO(kakkoyun): Check probability of this happening.
		panic("inconsistent state: objFile is nil")
	}

	if m.pprof != nil {
		return m.pprof
	}

	m.pprof = &profile.Mapping{
		ID:      uint64(m.id),
		Start:   uint64(m.StartAddr),
		Limit:   uint64(m.EndAddr),
		Offset:  uint64(m.Offset),
		BuildID: m.objFile.BuildID,
		File:    m.objFile.Path,
	}
	return m.pprof
}

func (ms *MapManager) MappingsForPID(pid int) (Mappings, error) {
	proc, err := ms.Proc(pid)
	if err != nil {
		return nil, err
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, err
	}

	res := make([]*Mapping, 0, len(maps))
	for i, m := range maps {
		res = append(res, &Mapping{id: i + 1, ProcMap: m})
	}
	return res, nil
}

func (ms Mappings) MappingForAddr(addr uint64) *Mapping {
	for _, m := range ms {
		// Only consider executable mappings.
		if m.Perms.Execute {
			if uint64(m.StartAddr) <= addr && uint64(m.EndAddr) >= addr {
				return m
			}
		}
	}

	return nil
}
