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

package maps

import (
	"errors"

	"github.com/google/pprof/profile"
)

var ErrNotFound = errors.New("not found")

type Mapping struct {
	fileCache   *PIDMappingFileCache
	pidMappings map[uint32][]*profile.Mapping
	pids        []uint32
}

func NewMapping(fileCache *PIDMappingFileCache) *Mapping {
	return &Mapping{
		fileCache:   fileCache,
		pidMappings: map[uint32][]*profile.Mapping{},
		pids:        []uint32{},
	}
}

func (m *Mapping) PIDAddrMapping(pid uint32, addr uint64) (*profile.Mapping, error) {
	maps, ok := m.pidMappings[pid]
	if !ok {
		var err error
		maps, err = m.fileCache.MappingForPID(pid)
		if err != nil {
			return nil, err
		}
		m.pidMappings[pid] = maps
		m.pids = append(m.pids, pid)
	}

	return mappingForAddr(maps, addr), nil
}

type ProcessMapping struct {
	PID     uint32
	Mapping *profile.Mapping
}

func (m *Mapping) AllMappings() ([]*profile.Mapping, []ProcessMapping) {
	res := []*profile.Mapping{}
	mappedFiles := []ProcessMapping{}
	i := uint64(1) // Mapping IDs need to start with 1 in pprof.
	for _, pid := range m.pids {
		maps := m.pidMappings[pid]
		for _, mapping := range maps {
			if mapping.BuildID != "" {
				mappedFiles = append(mappedFiles, ProcessMapping{
					PID:     pid,
					Mapping: mapping,
				})
			}
			// TODO(brancz): Do we need to handle potentially duplicate
			// vdso/vsyscall mappings?
			mapping.ID = i
			res = append(res, mapping)
			i++
		}
	}

	return res, mappedFiles
}

func mappingForAddr(mapping []*profile.Mapping, addr uint64) *profile.Mapping {
	for _, m := range mapping {
		if m.Start <= addr && m.Limit >= addr {
			return m
		}
	}

	return nil
}
