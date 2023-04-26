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
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sourcegraph/conc/pool"
	"golang.org/x/sync/singleflight"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

// TODO(kakkoyun) Add metrics !!
type metrics struct{}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{}
	return m
}

type InfoManager struct {
	metrics *metrics
	logger  log.Logger

	cache burrow.Cache
	sfg   singleflight.Group // for loader.

	mapManager       *MapManager
	debuginfoManager *debuginfo.Manager
}

func NewInfoManager(logger log.Logger, reg prometheus.Registerer, mm *MapManager, dim *debuginfo.Manager, profilingDuration time.Duration) *InfoManager {
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
		sfg:              singleflight.Group{},
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
		return nil, nil
	})

	return err
}

func (im *InfoManager) extractAndUploadDebuginfo(ctx context.Context, pid int, mappings Mappings) error {
	di := im.debuginfoManager

	// TODO(kakkoyun): We can have simpler type.
	type uploadResult struct {
		objFile *objectfile.ObjectFile
		err     error
	}

	// TODO(kakkoyun): Experiment with stream.
	p := pool.NewWithResults[uploadResult]().
		WithMaxGoroutines(10).
		WithContext(ctx).
		WithCollectErrored()

	var multiErr *multierror.Error
	for _, m := range mappings {
		if !m.isOpen() {
			// TODO(kakkoyun): Do we need this check?
			// Make sure this never happens at this stage.
			multiErr = multierror.Append(multiErr, fmt.Errorf("mapping %s is not open", m.Pathname))
			continue
		}

		objFile := m.objFile
		logger := log.With(im.logger, "buildid", objFile.BuildID, "path", objFile.Path)

		// We upload the debug information files concurrently. In case
		// of two files with the same buildID are extracted at the same
		// time, they will be written to the same file.
		//
		// Most of the time, the file is, erm, eventually consistent-ish,
		// and once all the writers are done, the debug file looks as an ELF
		// with the correct bytes.
		//
		// However, I don't believe there's any guarantees on this, so the
		// files aren't getting corrupted most of the time by sheer luck.
		//
		// The singleflight group makes sure that we don't try to extract
		// the same buildID concurrently.

		// TODO(kakkoyun): Update comment above.
		// - Make sure this is called ASAP to narrow-down the window.
		// - Make sure the file handle is obtain as soon as possible.
		if err := di.ExtractOrFindDebugInfo(ctx, m.Root(), objFile); err != nil {
			level.Error(logger).Log("msg", "failed to ensure debuginfo is uploaded", "err", err)
		}

		p.Go(func(ctx context.Context) (uploadResult, error) {
			expbackOff := backoff.NewExponentialBackOff()
			err := backoff.Retry(func() error {
				// NOTICE: There is an upload timeout duration that's controlled by a flag in the debuginfo manager.
				err := di.Upload(ctx, objFile)
				// if err != nil {
				// 	return uploadResult{objFile: objFile, err: err}, nil
				// }
				// return uploadResult{objFile: objFile, err: nil}, nil
				// Only enter this block if retrying
				if err != nil && expbackOff.NextBackOff().Nanoseconds() > 0 {
					// TODO(kakkoyun):
					// - What could be a permenent error?
					// im.metrics.uploadRetries.Inc()
					level.Debug(im.logger).Log(
						"msg", "failed to upload debug information, will retry",
						"retry", expbackOff.NextBackOff(),
						"err", err,
					)
				}
				return err
			}, expbackOff)
			return uploadResult{objFile: objFile, err: err}, nil
		})
	}

	go func() {
		// TODO(kakkoyun):
		// - Retry logic.
		// - How to keep track of success and failures?
		// - Permanent failure?
		// - Make sure uploading nit blocked because of retries.
		// - Where should the retry logic go here or debug information uploader.

		// TODO(kakkoyun):
		// - IF successful, close the objectfile. We just need to make sure all the info needed is extracted.
		// - IF failure, retry.
		// - IF an unrecoverable/retry limit exceed. Close the objectfile. And record the failure.
		// - Add metrics.
		// - Make sure this doesn't block the group.
		results, err := p.Wait()
		if err != nil {
			level.Error(im.logger).Log("msg", "failed to ensure ALL debuginfo is uploaded", "err", err)
		}
		for _, r := range results {
			logger := log.With(im.logger, "buildid", r.objFile.BuildID, "path", r.objFile.Path)
			if r.err != nil {
				level.Error(logger).Log("msg", "failed to ensure debuginfo is uploaded", "err", r.err)
			}
			if err := r.objFile.Close(); err != nil {
				level.Error(logger).Log("msg", "failed to close objectfile", "err", err)
			}
		}
	}()

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

// Normalize returns the normalized address for the given address
// if the given address within the range of process' mappings.
func (i *Info) Normalize(addr uint64) (uint64, error) {
	m := i.Mappings.MappingForAddr(addr)
	if m == nil {
		return 0, errors.New("mapping is nil")
	}

	// Transform the address using calculated base address for the binary.
	normalizedAddr, err := m.Normalize(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to get normalized address from object file: %w", err)
	}

	return normalizedAddr, nil
}
