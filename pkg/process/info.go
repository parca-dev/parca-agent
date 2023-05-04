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
	"fmt"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type DebuginfoManager interface {
	ExtractOrFindDebugInfo(context.Context, string, *objectfile.ObjectFile) error
	UploadWithRetry(context.Context, *objectfile.ObjectFile) error
	Upload(context.Context, *objectfile.ObjectFile) error
	Close() error
}

// TODO(kakkoyun): Add metrics !!
type metrics struct{}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{}
	return m
}

type InfoManager struct {
	metrics *metrics
	logger  log.Logger

	cache burrow.Cache
	sfg   *singleflight.Group // for loader.

	mapManager       *MapManager
	debuginfoManager DebuginfoManager
}

func NewInfoManager(logger log.Logger, reg prometheus.Registerer, mm *MapManager, dim DebuginfoManager, profilingDuration time.Duration) *InfoManager {
	return &InfoManager{
		logger:  logger,
		metrics: newMetrics(reg),
		cache: burrow.New(
			burrow.WithMaximumSize(5000),
			burrow.WithExpireAfterAccess(10*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "process_info")),
		),
		mapManager:       mm,
		debuginfoManager: dim,
		sfg:              &singleflight.Group{},
	}
}

type Info struct {
	// TODO(kakkoyun): Put all the necessary (following) fields in this struct.
	// - PerfMaps
	// - Unwind Information
	Mappings Mappings
}

// Load collects the required information for a process and stores it for future needs.
func (im *InfoManager) Load(ctx context.Context, pid int) error {
	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	if _, exists := im.cache.GetIfPresent(pid); exists {
		return nil
	}

	_, err, _ := im.sfg.Do(strconv.Itoa(pid), func() (interface{}, error) {
		mappings, err := im.mapManager.MappingsForPID(pid)
		if err != nil {
			return nil, err
		}

		// Upload debug information of the discovered object files.
		if im.debuginfoManager != nil {
			if err := im.extractAndUploadDebuginfo(ctx, pid, mappings); err != nil {
				level.Warn(im.logger).Log("msg", "failed to upload debug information", "err", err)
			}
		}

		im.cache.Put(pid, Info{
			Mappings: mappings,
		})
		return nil, nil //nolint:nilnil
	})

	return err
}

func (im *InfoManager) extractAndUploadDebuginfo(ctx context.Context, pid int, mappings Mappings) error {
	var (
		di       = im.debuginfoManager
		multiErr *multierror.Error
	)
	for _, m := range mappings {
		if !m.isSymbolizable() {
			continue
		}

		if !m.isOpen() {
			if err := m.openObjFile(); err != nil {
				level.Debug(im.logger).Log("msg", "failed to re-open objfile", "err", err)
			}
			multiErr = multierror.Append(multiErr, fmt.Errorf("mapping %s is not open", m.Pathname))
			continue
		}

		objFile := m.objFile // objectfile should exist and be open at this point.
		logger := log.With(im.logger, "pid", pid, "buildid", objFile.BuildID, "path", objFile.Path)

		// We upload the debug information files asynchronous and concurrently with retry.
		// However, first we need to find the debuginfo file or extract debuginfo from the executable.
		// For the short-lived processes, we may not complete the operation before the process exits.
		// Therefore, to be able shorten this window as much as possible, we extract and find the debuginfo
		// files synchronously and upload them asynchronously.
		// We still might be too slow to obtain the necessary file descriptors for certain short-lived processes.
		if err := di.ExtractOrFindDebugInfo(ctx, m.Root(), objFile); err != nil {
			level.Error(logger).Log("msg", "failed to find or extract debuginfo is uploaded", "err", err)
			multiErr = multierror.Append(multiErr, err)
			continue
		}

		go func() {
			// TODO(kakkoyun):
			// Add metrics to keep track of success and failures.
			// And duration.
			logger := log.With(im.logger, "buildid", objFile.BuildID, "path", objFile.Path)

			// NOTICE: The upload timeout and upload retry count controlled by debuginfo manager.
			if err := di.UploadWithRetry(ctx, objFile); err != nil {
				// TODO(kakkoyun): Should we keep the file open or closed?
				level.Error(logger).Log("msg", "failed to upload debuginfo", "err", err)
				return
			}

			objFile.MarkUploaded()
			if err := objFile.Close(); err != nil {
				level.Debug(logger).Log("msg", "failed to close objfile", "err", err)
			}
		}()
	}
	return multiErr.ErrorOrNil()
}

// Get returns the cached information for the given process.
func (im *InfoManager) Get(ctx context.Context, pid int) (*Info, error) {
	v, ok := im.cache.GetIfPresent(pid)
	if !ok {
		if err := im.Load(ctx, pid); err != nil {
			return nil, err
		}
		v, ok = im.cache.GetIfPresent(pid)
		if !ok {
			// understand why an item might not be in cache.
			return nil, fmt.Errorf("failed to load debug information for pid %d", pid)
		}
	}

	info, ok := v.(Info)
	if !ok {
		panic("received the wrong type in the info cache")
	}
	return &info, nil
}
