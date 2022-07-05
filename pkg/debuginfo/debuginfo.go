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
	"debug/elf"
	"errors"
	"io"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	"github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/rzajac/flexbuf"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var errNotFound = errors.New("not found")

type DebugInfo struct {
	logger log.Logger
	client Client

	existsCache       cache.Cache
	debugInfoSrcCache cache.Cache
	uploadingCache    cache.Cache

	*Extractor
	*Uploader
	*Finder
}

// New creates a new DebugInfo.
func New(logger log.Logger, client Client) *DebugInfo {
	return &DebugInfo{
		logger: logger,
		client: client,
		existsCache: cache.New(
			cache.WithMaximumSize(128),                // Arbitrary cache size.
			cache.WithExpireAfterWrite(2*time.Minute), // Arbitrary period.
		),
		debugInfoSrcCache: cache.New(cache.WithMaximumSize(128)), // Arbitrary cache size.
		// Up to this amount of debug files in flight at once. This number is very large
		// and unlikely to happen in real life.
		uploadingCache: cache.New(
			cache.WithMaximumSize(1024),
		),
		Finder:    NewFinder(logger),
		Extractor: NewExtractor(logger),
		Uploader:  NewUploader(logger, client),
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
// However I don't believe there's any guarantees on this, so the
// files aren't getting corrupted most of the time by sheer luck.
//
// These two helpers make sure that we don't try to extract + upload
// the same buildID concurrently.
func (di *DebugInfo) alreadyUploading(buildID string) bool {
	_, ok := di.uploadingCache.GetIfPresent(buildID)
	return ok
}

func (di *DebugInfo) markAsUploading(buildID string) {
	di.uploadingCache.Put(buildID, true)
}

func (di *DebugInfo) removeAsUploading(buildID string) {
	di.uploadingCache.Invalidate(buildID)
}

// EnsureUploaded ensures that the extracted or the found debuginfo for the given buildID is uploaded.
func (di *DebugInfo) EnsureUploaded(ctx context.Context, objFiles []*objectfile.MappedObjectFile) {
	for _, objFile := range objFiles {
		buildID := objFile.BuildID
		logger := log.With(di.logger, "buildid", buildID, "path", objFile.Path)

		if di.alreadyUploading(buildID) {
			continue
		}
		di.markAsUploading(buildID)

		src := di.debugInfoSrcPath(ctx, buildID, objFile)
		if src == "" {
			continue
		}
		if exists := di.exists(ctx, buildID, src); exists {
			continue
		}

		buf := flexbuf.New()
		if err := di.Extract(ctx, buf, src); err != nil {
			level.Debug(di.logger).Log("msg", "failed to extract debug information", "err", err, "buildID", buildID, "path", src)
			continue
		}

		buf.SeekStart()
		if err := validate(buf); err != nil {
			level.Debug(logger).Log("msg", "failed to validate debug information", "err", err, "buildID", buildID, "path", src)
			continue
		}

		buf.SeekStart()
		// If we found a debuginfo file, either in file or on the system, we upload it to the server.
		if err := di.Upload(ctx, SourceInfo{BuildID: buildID, Path: src}, buf); err != nil {
			if errors.Is(err, debuginfo.ErrDebugInfoAlreadyExists) {
				// If already exists, we should mark as exists in cache!
				di.existsCache.Put(buildID, struct{}{})
				level.Debug(logger).Log("msg", "debug information has already been uploaded or exists in server")
				continue
			}
			level.Error(logger).Log("msg", "failed to upload debug information", "err", err)
			continue
		}

		di.removeAsUploading(buildID)
		level.Debug(logger).Log("msg", "debug information uploaded successfully")
	}
}

func (di *DebugInfo) exists(ctx context.Context, buildID, src string) bool {
	logger := log.With(di.logger, "buildid", buildID, "path", src)
	if _, ok := di.existsCache.GetIfPresent(buildID); ok {
		level.Debug(logger).Log("msg", "debug information already exists in the server", "source", "cache")
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
		level.Debug(logger).Log("msg", "debug information already exists in the server", "source", "server")
		di.existsCache.Put(buildID, struct{}{})
		return true
	}

	level.Debug(logger).Log("msg", "could not find symbols in server")
	return false
}

func (di *DebugInfo) debugInfoSrcPath(ctx context.Context, buildID string, objFile *objectfile.MappedObjectFile) string {
	logger := log.With(di.logger, "buildid", buildID, "path", objFile.Path)
	if val, ok := di.debugInfoSrcCache.GetIfPresent(buildID); ok {
		//nolint:forcetypeassert
		return val.(string)
	}

	// First, check whether debuginfos have been installed separately,
	// typically in /usr/lib/debug, so we try to discover if there is a debuginfo file,
	// that has the same build ID as the object.
	dbgInfoPath, err := di.Find(ctx, objFile)
	if err == nil && dbgInfoPath != "" {
		level.Debug(logger).Log("msg", "found debug information in /usr/lib/debug")
		di.debugInfoSrcCache.Put(buildID, dbgInfoPath)
		return dbgInfoPath
	}
	level.Debug(logger).Log("msg", "failed to find debug information on the system", "err", err)

	di.debugInfoSrcCache.Put(buildID, objFile.Path)
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
