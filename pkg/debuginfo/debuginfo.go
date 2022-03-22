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

package debuginfo

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	"github.com/parca-dev/parca/pkg/debuginfo"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var errNotFound = errors.New("not found")

type Client interface {
	Exists(ctx context.Context, buildID string) (bool, error)
	Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error)
}

type NoopClient struct{}

func (c *NoopClient) Exists(ctx context.Context, buildID string) (bool, error) {
	return true, nil
}

func (c *NoopClient) Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error) {
	return 0, nil
}

func NewNoopClient() Client {
	return &NoopClient{}
}

type DebugInfo struct {
	logger log.Logger
	client Client

	existsCache        cache.Cache
	debugInfoFileCache cache.Cache

	*Extractor
	*Uploader
	*Finder
}

// New creates a new DebugInfo.
func New(logger log.Logger, client Client, tmp string) *DebugInfo {
	return &DebugInfo{
		logger: logger,
		existsCache: cache.New(
			cache.WithMaximumSize(128),                // Arbitrary cache size.
			cache.WithExpireAfterWrite(2*time.Minute), // Arbitrary period.
		),
		debugInfoFileCache: cache.New(cache.WithMaximumSize(128)), // Arbitrary cache size.
		client:             client,
		Extractor:          NewExtractor(logger, client, tmp),
		Uploader:           NewUploader(logger, client),
		Finder:             NewFinder(logger),
	}
}

// EnsureUploaded ensures that the extracted or the found debuginfo for the given buildID is uploaded.
func (di *DebugInfo) EnsureUploaded(ctx context.Context, objFiles []*objectfile.MappedObjectFile) {
	for _, objFile := range objFiles {
		buildID := objFile.BuildID
		logger := log.With(di.logger, "buildid", buildID, "path", objFile.Path)

		if exists := di.exists(ctx, buildID, objFile.Path); exists {
			continue
		}

		// Finds the debuginfo file. Interim files can be clean up.
		dbgInfoPath, shouldCleanup := di.debugInfoFilePath(ctx, buildID, objFile)
		// If debuginfo file is still not found, we don't need to upload anything.
		if dbgInfoPath == "" {
			level.Warn(logger).Log("msg", "failed to find debug info")
			continue
		}

		// If we found a debuginfo file, either in file or on the system, we upload it to the server.
		if err := di.Upload(ctx, buildID, dbgInfoPath); err != nil {
			if errors.Is(err, debuginfo.ErrDebugInfoAlreadyExists) {
				// If already exists, we should mark as exists in cache!
				di.existsCache.Put(buildID, struct{}{})
				level.Debug(logger).Log("msg", "debug info already exists")
				continue
			}
			level.Error(logger).Log("msg", "failed to upload debug info", "err", err)
			continue
		}
		level.Debug(logger).Log("msg", "debug info uploaded successfully")

		// Successfully uploaded, we can clean up.
		// Cleanup the extracted debug info file.
		if shouldCleanup {
			if err := os.Remove(dbgInfoPath); err != nil {
				if os.IsNotExist(err) {
					di.debugInfoFileCache.Invalidate(buildID)
					continue
				}
				level.Debug(logger).Log("msg", "failed to cleanup debug info", "err", err)
				continue
			}
			di.debugInfoFileCache.Invalidate(buildID)
		}
	}
}

func (di *DebugInfo) exists(ctx context.Context, buildID, filePath string) bool {
	logger := log.With(di.logger, "buildid", buildID, "path", filePath)
	if _, ok := di.existsCache.GetIfPresent(buildID); ok {
		level.Debug(logger).Log("msg", "debug info already uploaded to server")
		return true
	}

	exists, err := di.client.Exists(ctx, buildID)
	if err != nil {
		level.Debug(logger).Log(
			"msg", "failed to check whether build ID symbol exists",
			"buildid", buildID, "err", err,
		)
	}

	if exists {
		level.Debug(logger).Log("msg", "debug information already exist in server")
		di.existsCache.Put(buildID, struct{}{})
		return true
	}

	level.Debug(logger).Log("msg", "could not find symbols in server")
	return false
}

func (di *DebugInfo) debugInfoFilePath(ctx context.Context, buildID string, objFile *objectfile.MappedObjectFile) (string, bool) {
	type result struct {
		path          string
		shouldCleanup bool
	}
	if val, ok := di.debugInfoFileCache.GetIfPresent(buildID); ok {
		res := val.(result)
		return res.path, res.shouldCleanup
	}

	dbgInfoPath, err := di.Extract(ctx, buildID, objFile.Path)
	if err == nil && dbgInfoPath != "" {
		di.debugInfoFileCache.Put(buildID, result{dbgInfoPath, true})
		return dbgInfoPath, true
	}

	// err != nil || dbgInfoPath == ""
	level.Debug(di.logger).Log(
		"msg", "failed to extract debug information",
		"buildid", buildID, "path", objFile.Path, "err", err,
	)

	// The object does not have debug symbols, but maybe debuginfos
	// have been installed separately, typically in /usr/lib/debug, so
	// we try to discover if there is a debuginfo file, that has the
	// same build ID as the object.
	dbgInfoPath, err = di.Find(ctx, objFile.BuildID, objFile.Root())
	if err != nil {
		level.Warn(di.logger).Log("msg", "failed to find debug info on the system", "err", err)
	}
	// Even if finder returns empty string, it doesn't matter extractor already failed.
	di.debugInfoFileCache.Put(buildID, result{path: dbgInfoPath, shouldCleanup: false})
	return dbgInfoPath, false
}
