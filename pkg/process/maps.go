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

package process

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/hash"
)

type mappingFileCache struct {
	logger     log.Logger
	fs         fs.FS
	cache      map[int][]*profile.Mapping
	pidMapHash map[int]uint64
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func NewMappingFileCache(logger log.Logger) *mappingFileCache {
	return &mappingFileCache{
		logger:     logger,
		fs:         &realfs{},
		cache:      map[int][]*profile.Mapping{},
		pidMapHash: map[int]uint64{},
	}
}

func (c *mappingFileCache) MappingForPID(pid int) ([]*profile.Mapping, error) {
	m, err := c.mappingForPID(pid)
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

func (c *mappingFileCache) mappingForPID(pid int) ([]*profile.Mapping, error) {
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	h, err := hash.File(c.fs, mapsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
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
			//  m.File == "[vdso]" || m.File == "[vsyscall]" || m.File == "[stack]" || m.File == "[heap]"
			if m.Unsymbolizable() || m.File == "" {
				continue
			}

			abs := path.Join(fmt.Sprintf("/proc/%d/root", pid), m.File)
			m.BuildID, err = buildid.BuildID(abs)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					level.Debug(c.logger).Log("msg", "failed to read object build ID", "object", abs, "err", err)
				}
				continue
			}
		}
	}

	c.cache[pid] = mapping
	return mapping, nil
}
