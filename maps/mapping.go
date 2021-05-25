package maps

import (
	"github.com/google/pprof/profile"
)

type Mapping struct {
	fileCache   *PidMappingFileCache
	pidMappings map[uint32][]*profile.Mapping
	pids        []uint32
}

func NewMapping(fileCache *PidMappingFileCache) *Mapping {
	return &Mapping{
		fileCache:   fileCache,
		pidMappings: map[uint32][]*profile.Mapping{},
		pids:        []uint32{},
	}
}

func (m *Mapping) PidAddrMapping(pid uint32, addr uint64) (*profile.Mapping, error) {
	maps, ok := m.pidMappings[pid]
	if !ok {
		var err error
		maps, err = m.fileCache.MappingForPid(pid)
		if err != nil {
			return nil, err
		}
		m.pidMappings[pid] = maps
		m.pids = append(m.pids, pid)
	}

	return mappingForAddr(maps, addr), nil
}

func (m *Mapping) AllMappings() []*profile.Mapping {
	res := []*profile.Mapping{}
	i := uint64(1) // Mapping IDs need to start with 1 in pprof.
	for _, pid := range m.pids {
		maps := m.pidMappings[pid]
		for _, mapping := range maps {
			// TODO(brancz): Do we need to handle potentially duplicate
			// vdso/vsyscall mappings?
			mapping.ID = i
			res = append(res, mapping)
			i++
		}
	}
	return res
}

func mappingForAddr(mapping []*profile.Mapping, addr uint64) *profile.Mapping {
	for _, m := range mapping {
		if m.Start <= addr && m.Limit >= addr {
			return m
		}
	}

	return nil
}
