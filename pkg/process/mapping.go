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
	"errors"
	"sync"

	"github.com/google/pprof/profile"
)

var ErrNotFound = errors.New("not found")

type MappingCache interface {
	MappingForPID(pid int) ([]*profile.Mapping, error)
}

type Mapping struct {
	cache       MappingCache
	pidMappings map[int][]*profile.Mapping
	mutex       sync.Mutex
}

func NewMapping(cache MappingCache) *Mapping {
	return &Mapping{
		cache:       cache,
		pidMappings: map[int][]*profile.Mapping{},
	}
}

func (m *Mapping) PopulateMappings(pid int) ([]*profile.Mapping, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	maps, ok := m.pidMappings[pid]
	if !ok {
		var err error
		maps, err = m.cache.MappingForPID(pid)
		if err != nil {
			return nil, err
		}
		m.pidMappings[pid] = maps
	}

	return maps, nil
}

func (m *Mapping) PIDAddrMapping(pid int, addr uint64) (*profile.Mapping, error) {
	maps, err := m.PopulateMappings(pid)
	if err != nil {
		return nil, err
	}

	return mappingForAddr(maps, addr), nil
}

type Map struct {
	PID     int
	Mapping *profile.Mapping
}

func (m *Mapping) allMappings() ([]*profile.Mapping, []Map) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	res := []*profile.Mapping{}
	mappedFiles := []Map{}
	i := uint64(1) // Mapping IDs need to start with 1 in pprof.
	for pid := range m.pidMappings {
		maps := m.pidMappings[pid]
		for _, mapping := range maps {
			if mapping.BuildID != "" {
				mappedFiles = append(mappedFiles, Map{
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

func (m *Mapping) MappingsForPID(pid int) []*profile.Mapping {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	res := []*profile.Mapping{}
	i := uint64(1) // Mapping IDs need to start with 1 in pprof.
	maps := m.pidMappings[pid]
	for _, mapping := range maps {
		// TODO(brancz): Do we need to handle potentially duplicate vdso/vsyscall mappings?
		mapping.ID = i
		res = append(res, mapping)
		i++
	}
	return res
}

func (m *Mapping) MapsForPID(pid int) []Map {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	mappedFiles := []Map{}
	maps := m.pidMappings[pid]
	for _, mapping := range maps {
		if mapping.BuildID != "" {
			mappedFiles = append(mappedFiles, Map{
				PID:     pid,
				Mapping: mapping,
			})
		}
	}
	return mappedFiles
}

func mappingForAddr(mapping []*profile.Mapping, addr uint64) *profile.Mapping {
	for _, m := range mapping {
		if m.Start <= addr && m.Limit >= addr {
			return m
		}
	}

	return nil
}
