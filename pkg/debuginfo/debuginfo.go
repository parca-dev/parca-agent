// Copyright 2021 The Parca Authors
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

package debuginfo

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	lru "github.com/hashicorp/golang-lru"

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

	existsCache        *lru.ARCCache
	debugInfoFileCache *lru.ARCCache

	*Extractor
	*Uploader
	*Finder
}

// New creates a new DebugInfo.
func New(logger log.Logger, client Client, tmp string) *DebugInfo {
	ec, err := lru.NewARC(128) // Arbitrary cache size.
	if err != nil {
		level.Warn(logger).Log("msg", "failed to initialize exists cache", "err", err)
	}
	dc, err := lru.NewARC(128) // Arbitrary cache size.
	if err != nil {
		level.Warn(logger).Log("msg", "failed to initialize debug info cache", "err", err)
	}
	return &DebugInfo{
		logger:             logger,
		existsCache:        ec,
		debugInfoFileCache: dc,
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

		if exists := di.exists(ctx, buildID, objFile.Path); exists {
			continue
		}

		// Finds the debuginfo file. Interim files can be clean up.
		dbgInfoPath, shouldCleanup := di.debugInfoFilePath(ctx, buildID, objFile)
		// If debuginfo file is still not found, we don't need to upload anything.
		if dbgInfoPath == "" {
			level.Warn(di.logger).Log(
				"msg", "failed to find debug info",
				"buildid", objFile.BuildID, "path", objFile.Path,
			)
			continue
		}

		// If we found a debuginfo file, either in file or on the system, we upload it to the server.
		if err := di.Upload(ctx, objFile.BuildID, dbgInfoPath); err != nil {
			level.Error(di.logger).Log("msg", "failed to upload debug info", "err", err)
			continue
		}

		level.Debug(di.logger).Log(
			"msg", "debug info uploaded successfully",
			"buildid", objFile.BuildID, "path", objFile.Path,
		)

		// Successfully uploaded, we can clean up.
		// Cleanup the extracted debug info file.
		if shouldCleanup {
			if err := os.Remove(dbgInfoPath); err != nil {
				if os.IsNotExist(err) {
					di.debugInfoFileCache.Remove(buildID)
					continue
				}
				level.Debug(di.logger).Log("msg", "failed to cleanup debug info", "err", err)
				continue
			}
			di.debugInfoFileCache.Remove(buildID)
		}
	}
}

func (di *DebugInfo) exists(ctx context.Context, buildID, filePath string) bool {
	// TODO(kakkoyun): Enable.
	//if _, ok := di.existsCache.Get(buildID); ok {
	//	level.Debug(di.logger).Log("msg", "debug info already uploaded to server", "buildid", buildID, "path", filePath)
	//	return true
	//}

	exists, err := di.client.Exists(ctx, buildID)
	if err != nil {
		level.Debug(di.logger).Log(
			"msg", "failed to check whether build ID symbol exists",
			"buildid", buildID, "err", err,
		)
	}

	if exists {
		level.Debug(di.logger).Log(
			"msg", "debug information already exist in server",
			"buildid", buildID, "path", filePath,
		)
		di.existsCache.Add(buildID, struct{}{})
		return true
	}

	level.Debug(di.logger).Log(
		"msg", "could not find symbols in server",
		"buildid", buildID, "path", filePath,
	)
	return false
}

func (di *DebugInfo) debugInfoFilePath(ctx context.Context, buildID string, objFile *objectfile.MappedObjectFile) (string, bool) {
	type result struct {
		path          string
		shouldCleanup bool
	}
	// TODO(kakkoyun): Enable.
	//if val, ok := di.debugInfoFileCache.Get(buildID); ok {
	//	res := val.(result)
	//	return res.path, res.shouldCleanup
	//}

	dbgInfoPath, err := di.Extract(ctx, buildID, objFile.Path)
	if err == nil && dbgInfoPath != "" {
		di.debugInfoFileCache.Add(buildID, result{dbgInfoPath, true})
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
	di.debugInfoFileCache.Add(buildID, result{path: dbgInfoPath, shouldCleanup: false})
	return dbgInfoPath, false
}
