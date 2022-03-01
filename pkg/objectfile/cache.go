// Copyright 2022 The Parca Authors
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

package objectfile

import (
	"fmt"
	"path"
	"strconv"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"
	lru "github.com/hashicorp/golang-lru"
)

type Cache interface {
	ObjectFileForProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error)
}

type cache struct {
	cache *lru.ARCCache
}

type noopCache struct{}

func (n noopCache) ObjectFileForProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error) {
	return fromProcess(pid, m)
}

// NewCache creates a new cache for object files.
func NewCache(logger log.Logger, size int) Cache {
	c, err := lru.NewARC(size)
	if err != nil {
		level.Warn(logger).Log("msg", "failed to initialize cache", "err", err)
		return &noopCache{}
	}
	return &cache{cache: c}
}

// ObjectFileForProcess returns the object file for the given mapping and process id.
// If object file is already in the cache, it is returned.
// Otherwise, the object file is loaded from the file system.
func (c *cache) ObjectFileForProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error) {
	if val, ok := c.cache.Get(m.BuildID); ok {
		return val.(*MappedObjectFile), nil
	}

	objFile, err := fromProcess(pid, m)
	if err != nil {
		return nil, err
	}

	c.cache.Add(m.BuildID, objFile)
	return objFile, nil
}

// fromProcess opens the specified executable or library file from the process.
func fromProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error) {
	filePath := path.Join("/proc", strconv.FormatUint(uint64(pid), 10), "/root", m.File)
	objFile, err := Open(filePath, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open mapped file: %v", err)
	}
	return &MappedObjectFile{ObjectFile: objFile, PID: pid, File: m.File}, nil
}
