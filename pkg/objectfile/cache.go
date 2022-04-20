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

package objectfile

import (
	"errors"
	"fmt"
	"path"
	"strconv"

	burrow "github.com/goburrow/cache"
	"github.com/google/pprof/profile"
)

type Cache interface {
	ObjectFileForProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error)
}

type cache struct {
	cache burrow.Cache
}

// NewCache creates a new cache for object files.
func NewCache(size int) Cache {
	return &cache{
		cache: burrow.New(burrow.WithMaximumSize(size)),
	}
}

// ObjectFileForProcess returns the object file for the given mapping and process id.
// If object file is already in the cache, it is returned.
// Otherwise, the object file is loaded from the file system.
func (c *cache) ObjectFileForProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error) {
	if val, ok := c.cache.GetIfPresent(cacheKey(pid, m)); ok {
		//nolint:forcetypeassert
		return val.(*MappedObjectFile), nil
	}

	objFile, err := fromProcess(pid, m)
	if err != nil {
		return nil, err
	}

	c.cache.Put(cacheKey(pid, m), objFile)
	return objFile, nil
}

// fromProcess opens the specified executable or library file from the process.
func fromProcess(pid uint32, m *profile.Mapping) (*MappedObjectFile, error) {
	if m.Unsymbolizable() {
		return nil, errors.New("unsymbolizable")
	}
	if m.File == "" {
		return nil, errors.New("cannot load object file for mappings with empty file")
	}

	filePath := path.Join("/proc", strconv.FormatUint(uint64(pid), 10), "/root", m.File)
	objFile, err := Open(filePath, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open mapped file: %w", err)
	}
	return &MappedObjectFile{ObjectFile: objFile, PID: pid, File: m.File}, nil
}

func cacheKey(pid uint32, m *profile.Mapping) string {
	return path.Join("/proc", strconv.FormatUint(uint64(pid), 10), m.BuildID)
}
