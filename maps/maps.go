package maps

import (
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/pprof/profile"
	"github.com/parca-dev/parca-agent/buildid"
	"github.com/parca-dev/parca-agent/hash"
)

type PidMappingFileCache struct {
	fs         fs.FS
	logger     log.Logger
	cache      map[uint32][]*profile.Mapping
	pidMapHash map[uint32]uint64
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func NewPidMappingFileCache(logger log.Logger) *PidMappingFileCache {
	return &PidMappingFileCache{
		fs:         &realfs{},
		logger:     logger,
		cache:      map[uint32][]*profile.Mapping{},
		pidMapHash: map[uint32]uint64{},
	}
}

func (c *PidMappingFileCache) MappingForPid(pid uint32) ([]*profile.Mapping, error) {
	m, err := c.mappingForPid(pid)
	if err != nil {
		return nil, err
	}

	res := make([]*profile.Mapping, 0, len(m))
	for _, mapping := range m {
		c := &profile.Mapping{}
		// This shallow copy is sufficient as profile.Mapping does not contain
		// any pointers.
		*c = *mapping
		res = append(res, c)
	}

	return res, nil
}

func (c *PidMappingFileCache) mappingForPid(pid uint32) ([]*profile.Mapping, error) {
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	h, err := hash.File(c.fs, mapsFile)
	if err != nil {
		return nil, err
	}
	if c.pidMapHash[pid] == h {
		return c.cache[pid], nil
	}
	c.pidMapHash[pid] = h

	f, err := c.fs.Open(mapsFile)
	if err != nil {
		return nil, err
	}

	mapping, err := profile.ParseProcMaps(f)
	if err != nil {
		return nil, err
	}

	for _, m := range mapping {
		// Try our best to have the BuildID.
		if m.BuildID == "" {
			// TODO(brancz): These need special cases.
			if m.File == "[vdso]" || m.File == "[vsyscall]" {
				continue
			}

			abs := path.Join(fmt.Sprintf("/proc/%d/root", pid), m.File)
			m.BuildID, err = buildid.ElfBuildID(abs)
			if err != nil {
				level.Warn(c.logger).Log("msg", "failed to read obj build ID", "obj", abs)
				continue
			}
		}
	}
	c.cache[pid] = mapping

	return mapping, nil
}
