// Copyright 2023 The Parca Authors
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

package process

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/go-kit/log"
	burrow "github.com/goburrow/cache"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type metrics struct{}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{}
	return m
}

type InfoManager struct {
	metrics *metrics

	logger log.Logger
	cache  burrow.Cache
	sfg    singleflight.Group

	mapManager       *MapManager
	debuginfoManager *debuginfo.Manager
}

func NewInfoManager(logger log.Logger, reg prometheus.Registerer, mm *MapManager, dim *debuginfo.Manager, profilingDuration time.Duration) *InfoManager {
	return &InfoManager{
		logger:  logger,
		metrics: newMetrics(reg),
		// TODO(kakkoyun): Convert loading cache.
		cache: burrow.New(
			burrow.WithMaximumSize(5000),
			// TODO: Remove the comment below.
			// @nocommit: Add jitter so we don't have to recompute the information
			// at the same time for many processes if many are evicted.
			// -- This should be good because the cache entries won't be created at the same and
			// -- they won't be accessed at the same time.
			burrow.WithExpireAfterAccess(10*profilingDuration),

			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "process_info_cache")),
		),
		mapManager:       mm,
		debuginfoManager: dim,
		sfg:              singleflight.Group{},
	}
}

type Info struct {
	// TODO(kakkoyun): Put all the following fields in a struct.
	// - PerfMaps
	// - Unwind Information
	Mappings Mappings
}

// ObtainInfo collects the required information for a process.
func (im *InfoManager) ObtainInfo(ctx context.Context, pid int) error {
	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	_, exists := im.cache.GetIfPresent(pid)
	if exists {
		return nil
	}

	_, err, _ := im.sfg.Do(strconv.Itoa(pid), func() (interface{}, error) {
		mappings, err := im.mapManager.MappingsForPID(pid)
		if err != nil {
			return nil, err
		}

		var errors *multierror.Error
		for _, m := range mappings {
			objFile, err := mappedObjectFile(pid, m)
			if err != nil {
				errors = multierror.Append(errors, err)
				continue
			}
			m.objFile = objFile
		}

		// Upload debug information of the discovered object files.
		if im.debuginfoManager != nil {
			// TODO: We need a retry mechanism here.
			objectFiles := make([]*objectfile.ObjectFile, 0, len(mappings))
			for _, mapping := range mappings {
				if mapping.objFile == nil {
					continue
				}
				objectFiles = append(objectFiles, mapping.objFile)
			}

			//
			// resultCh := make(chan error) // Create struct.
			// for _, objectFile := range objectFiles {
			// 	go func(objectFile *objectfile.ObjectFile) {
			// 		// Retry logic.
			// 		resultCh <- im.debuginfoManager.Upload(ctx, objectFile)
			// 	}(objectFile)
			// }

			// TODO(kakkoyun): Retry logic.
			// TODO(kakkoyun): Immediately call extractOrFindDebugInfo.
			// TODO(kakkoyun): How to keep track of success and failures?
			// TODO(kakkoyun): Permanent failure?
			im.debuginfoManager.EnsureUploaded(ctx, objectFiles)
		}

		im.cache.Put(pid, Info{
			Mappings: mappings,
		})
		return nil, errors.ErrorOrNil()
	})

	return err
}

func (im *InfoManager) InfoForPID(pid int) (*Info, error) {
	v, ok := im.cache.GetIfPresent(pid)
	if !ok {
		// understand why an item might not be in cache
		return nil, fmt.Errorf("not in cache")
	}

	info, ok := v.(Info)
	if !ok {
		panic("received the wrong type in the info cache")
	}

	return &info, nil
}

// mappedObjectFile opens the specified executable or library file from the process.
func mappedObjectFile(pid int, m *Mapping) (*objectfile.ObjectFile, error) {
	// TODO: Move to the caller.
	if m.Pathname == "" {
		return nil, errors.New("not found")
	}

	// TODO: Consider moving this inside of Open.
	fullPath := path.Join("/proc", strconv.Itoa(pid), "/root", m.Pathname)
	objFile, err := objectfile.Open(fullPath, uint64(m.StartAddr), uint64(m.EndAddr), uint64(m.Offset))
	if err != nil {
		return nil, fmt.Errorf("failed to open mapped file: %w", err)
	}
	// TODO: Consider assigning the pid to the builder.
	objFile.Pid = pid
	return objFile, nil
}

func (i *Info) Normalize(addr uint64) (uint64, error) {
	m := i.Mappings.MappingForAddr(addr)
	if m == nil {
		return 0, errors.New("mapping is nil")
	}

	objFile := m.objFile
	if objFile == nil {
		return 0, errors.New("objFile is nil")
	}

	// Transform the address using calculated base address for the binary.
	normalizedAddr, err := objFile.ObjAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to get normalized address from object file: %w", err)
	}

	return normalizedAddr, nil
}
