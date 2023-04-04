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

package objectfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/go-kit/log"
	burrow "github.com/goburrow/cache"
	"github.com/google/pprof/profile"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
)

type objfileCache struct {
	cache burrow.Cache
}

var ErrNoFile = errors.New("cannot load object file for mappings with empty file")

// NewCache creates a new cache for object files.
func NewCache(logger log.Logger, reg prometheus.Registerer, size int, profiligDuration time.Duration) *objfileCache {
	return &objfileCache{
		cache: burrow.New(
			burrow.WithMaximumSize(size),
			burrow.WithExpireAfterAccess(6*profiligDuration), // Invalidate it if it is not used for 6 profiling cycles (default).
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "objectfile")),
		),
	}
}

// ObjectFileForProcess returns the object file for the given mapping and process id.
// If object file is already in the cache, it is returned.
// Otherwise, the object file is loaded from the file system.
func (c *objfileCache) ObjectFileForProcess(pid int, m *profile.Mapping) (*MappedObjectFile, error) {
	if val, ok := c.cache.GetIfPresent(cacheKey(m)); ok {
		mappedObjFile, ok := val.(*MappedObjectFile)
		if !ok {
			return nil, errors.New("failed to convert cache result to MappedObjectFile")
		}
		return mappedObjFile, nil
	}

	objFile, err := fromProcess(pid, m)
	if err != nil {
		return nil, err
	}

	c.cache.Put(cacheKey(m), objFile)
	return objFile, nil
}

// fromProcess opens the specified executable or library file from the process.
func fromProcess(pid int, m *profile.Mapping) (*MappedObjectFile, error) {
	if m.Unsymbolizable() {
		return nil, errors.New("unsymbolizable")
	}
	if m.File == "" {
		return nil, ErrNoFile
	}

	filePath := path.Join("/proc", strconv.FormatInt(int64(pid), 10), "/root", m.File)
	objFile, err := Open(filePath, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open mapped file: %w", err)
	}
	return &MappedObjectFile{ObjectFile: objFile, PID: pid, File: m.File}, nil
}

func cacheKey(m *profile.Mapping) string {
	b := make([]byte, 3*8+len(m.BuildID))
	// use all field needed in MappedObjectFile.computeBase to build a unique key
	binary.BigEndian.PutUint64(b, m.Start)
	binary.BigEndian.PutUint64(b[8:], m.Limit)
	binary.BigEndian.PutUint64(b[16:], m.Offset)
	copy(b[24:], m.BuildID)
	return string(b)
}
