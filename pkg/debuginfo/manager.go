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
//

package debuginfo

import (
	"context"
	"debug/elf"
	"errors"
	"io"
	"os"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	"github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var errNotFound = errors.New("not found")

// Manager is a mechanism for extracting or finding the relevant debug information for the discovered executables.
type Manager struct {
	logger  log.Logger
	metrics *metrics
	client  Client

	stripDebuginfos bool
	tempDir         string

	existsCache       cache.Cache
	debuginfoSrcCache cache.Cache
	uploadingCache    cache.Cache

	*Extractor
	*Uploader
	*Finder
}

// New creates a new Manager.
func New(
	logger log.Logger,
	reg prometheus.Registerer,
	client Client,
	cacheTTL time.Duration,
	debugDirs []string,
	stripDebuginfos bool,
	tempDir string,
) *Manager {
	return &Manager{
		logger:  logger,
		metrics: newMetrics(reg),
		client:  client,
		existsCache: cache.New(
			cache.WithMaximumSize(512), // Arbitrary cache size.
			cache.WithExpireAfterWrite(cacheTTL),
		),
		debuginfoSrcCache: cache.New(cache.WithMaximumSize(128)), // Arbitrary cache size.
		// Up to this amount of debug files in flight at once. This number is very large
		// and unlikely to happen in real life.
		//
		// This cache doesn't have a time expiration since it is more used as a safety mechanism
		// than an actual cache. Object stored in this cache are getting removed at the end of each
		// profiler iteration.
		uploadingCache: cache.New(
			cache.WithMaximumSize(1024),
		),
		Finder:    NewFinder(logger, debugDirs),
		Extractor: NewExtractor(logger),
		Uploader:  NewUploader(logger, client),

		stripDebuginfos: stripDebuginfos,
		tempDir:         tempDir,
	}
}

// We upload the debug information files concurrently. In case
// of two files with the same buildID are extracted at the same
// time, they will be written to the same file.
//
// Most of the time, the file is, erm, eventually consistent-ish,
// and once all the writers are done, the debug file looks is an ELF
// with the correct bytes.
//
// However, I don't believe there's any guarantees on this, so the
// files aren't getting corrupted most of the time by sheer luck.
//
// These two helpers make sure that we don't try to extract + upload
// the same buildID concurrently.
func (di *Manager) alreadyUploading(buildID string) bool {
	_, ok := di.uploadingCache.GetIfPresent(buildID)
	return ok
}

func (di *Manager) markAsUploading(buildID string) {
	di.uploadingCache.Put(buildID, true)
}

func (di *Manager) removeAsUploading(buildID string) {
	di.uploadingCache.Invalidate(buildID)
}

// EnsureUploaded ensures that the extracted or the found debuginfo for the given buildID is uploaded.
func (di *Manager) EnsureUploaded(ctx context.Context, objFiles []*objectfile.MappedObjectFile) {
	for _, objFile := range objFiles {
		di.ensureUploaded(ctx, objFile)
	}
}

func (di *Manager) ensureUploaded(ctx context.Context, objFile *objectfile.MappedObjectFile) {
	buildID := objFile.BuildID
	path := objFile.Path

	logger := log.With(di.logger, "buildid", buildID, "path", path)

	if di.alreadyUploading(buildID) {
		return
	}
	di.markAsUploading(buildID)

	// removing the buildID from the cache to ensure a re-upload at the next interation.
	defer di.removeAsUploading(buildID)

	src := di.debuginfoSrcPath(ctx, buildID, objFile)
	if src == "" {
		return
	}
	if exists := di.exists(ctx, buildID, src); exists {
		return
	}

	var r io.Reader

	if di.stripDebuginfos {
		if err := os.MkdirAll(di.tempDir, 0o755); err != nil {
			level.Error(logger).Log("msg", "failed to create temp dir", "err", err)
			return
		}
		f, err := os.CreateTemp(di.tempDir, buildID)
		if err != nil {
			level.Error(logger).Log("msg", "failed to create temp file", "err", err)
			return
		}
		defer os.Remove(f.Name())

		if err := di.Extract(ctx, f, src); err != nil {
			level.Debug(logger).Log("msg", "failed to extract debug information", "err", err, "buildID", buildID, "path", src)
			return
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			level.Error(logger).Log("msg", "failed to seek to the beginning of the file", "err", err)
			return
		}
		if err := validate(f); err != nil {
			level.Debug(logger).Log("msg", "failed to validate debug information", "err", err, "buildID", buildID, "path", src)
			return
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			level.Error(logger).Log("msg", "failed to seek to the beginning of the file", "err", err)
			return
		}
		r = f
	} else {
		f, err := os.Open(src)
		if err != nil {
			level.Debug(logger).Log("msg", "failed to open debug information", "err", err, "buildID", buildID, "path", src)
			return
		}
		defer f.Close()

		r = f
	}

	// If we found a debuginfo file, either in file or on the system, we upload it to the server.
	if err := di.Upload(ctx, SourceInfo{BuildID: buildID, Path: src}, r); err != nil {
		di.metrics.uploadFailure.Inc()
		if errors.Is(err, debuginfo.ErrDebugInfoAlreadyExists) {
			di.existsCache.Put(buildID, struct{}{})
			return
		}
		level.Warn(logger).Log("msg", "failed to upload debug information", "err", err)
		return
	}
	di.metrics.uploadSuccess.Inc()
}

func (di *Manager) exists(ctx context.Context, buildID, src string) bool {
	logger := log.With(di.logger, "buildid", buildID, "path", src)
	if _, ok := di.existsCache.GetIfPresent(buildID); ok {
		return true
	}

	// Hash of the source file.
	h, err := hash.File(src)
	if err != nil {
		level.Debug(logger).Log("msg", "failed to hash file", "err", err)
	}

	exists, err := di.client.Exists(ctx, buildID, h)
	if err != nil {
		level.Debug(logger).Log("msg", "failed to check whether build ID symbol exists", "err", err)
	}

	if exists {
		di.existsCache.Put(buildID, struct{}{})
		return true
	}

	return false
}

func (di *Manager) debuginfoSrcPath(ctx context.Context, buildID string, objFile *objectfile.MappedObjectFile) string {
	if val, ok := di.debuginfoSrcCache.GetIfPresent(buildID); ok {
		str, ok := val.(string)
		if !ok {
			level.Error(log.With(di.logger)).Log("msg", "failed to convert buildID cache result to string")
		}
		return str
	}

	// First, check whether debuginfos have been installed separately,
	// typically in /usr/lib/debug, so we try to discover if there is a debuginfo file,
	// that has the same build ID as the object.
	dbgInfoPath, err := di.Find(ctx, objFile)
	if err == nil && dbgInfoPath != "" {
		di.debuginfoSrcCache.Put(buildID, dbgInfoPath)
		return dbgInfoPath
	}

	di.debuginfoSrcCache.Put(buildID, objFile.Path)
	return objFile.Path
}

func validate(f io.ReaderAt) error {
	elfFile, err := elf.NewFile(f)
	if err != nil {
		return err
	}
	defer elfFile.Close()

	if len(elfFile.Sections) == 0 {
		return errors.New("ELF does not have any sections")
	}
	return nil
}
