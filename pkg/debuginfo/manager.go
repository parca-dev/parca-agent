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

package debuginfo

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var errNotFound = errors.New("not found")

// Manager is a mechanism for extracting or finding the relevant debug information for the discovered executables.
type Manager struct {
	logger          log.Logger
	metrics         *metrics
	debuginfoClient debuginfopb.DebuginfoServiceClient
	sfg             singleflight.Group

	stripDebuginfos bool
	tempDir         string

	// hashCache caches ELF hashes (hashCacheKey is a key).
	hashCache                         *sync.Map
	shouldInitiateUploadResponseCache cache.Cache
	debuginfoSrcCache                 cache.Cache
	uploadingCache                    cache.Cache

	*Extractor
	*Finder

	uploadTimeoutDuration time.Duration
}

// New creates a new Manager.
func New(
	logger log.Logger,
	reg prometheus.Registerer,
	debuginfoClient debuginfopb.DebuginfoServiceClient,
	uploadTimeout time.Duration,
	cacheTTL time.Duration,
	debugDirs []string,
	stripDebuginfos bool,
	tempDir string,
) *Manager {
	return &Manager{
		logger:          logger,
		metrics:         newMetrics(reg),
		debuginfoClient: debuginfoClient,
		hashCache:       &sync.Map{},
		shouldInitiateUploadResponseCache: cache.New(
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

		sfg: singleflight.Group{},

		stripDebuginfos: stripDebuginfos,
		tempDir:         tempDir,

		uploadTimeoutDuration: uploadTimeout,
	}
}

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
	go func() {
		_, err, _ := di.sfg.Do("ensure-uploaded", func() (interface{}, error) {
			g := errgroup.Group{} // errgroup.WithContext doesn't work for this use case, we want to continue uploading even if one fails.
			g.SetLimit(4)         // Arbitrary limit.
			for _, objFile := range objFiles {
				logger := log.With(di.logger, "buildid", objFile.BuildID, "path", objFile.Path)
				objFile := objFile
				g.Go(func() error {
					ctx, cancel := context.WithTimeout(ctx, di.uploadTimeoutDuration)
					defer cancel()

					err := di.ensureUploaded(ctx, objFile)
					if err != nil {
						level.Error(logger).Log("msg", "failed to ensure debuginfo is uploaded", "err", err)
					}
					return nil
				})
			}
			return nil, g.Wait()
		})
		if err != nil {
			level.Error(di.logger).Log("msg", "ensure upload run failed", "err", err)
		}
	}()
}

// hashCacheKey is a cache key to retrieve the hashes of debuginfo files.
// Caching reduces allocs by 7.22% (33 kB/operation less) in ensureUpload,
// and it shaves 4 allocs per operation.
type hashCacheKey struct {
	buildID string
	modtime int64
}

func (di *Manager) ensureUploaded(ctx context.Context, objFile *objectfile.MappedObjectFile) error {
	buildID := objFile.BuildID
	if di.alreadyUploading(buildID) {
		return nil
	}
	di.markAsUploading(buildID)

	// removing the buildID from the cache to ensure a re-upload at the next interation.
	defer di.removeAsUploading(buildID)

	if shouldInitiateUpload := di.shouldInitiateUpload(ctx, buildID, objFile.File); !shouldInitiateUpload {
		return nil
	}

	src := di.debuginfoSrcPath(ctx, buildID, objFile)
	if src == "" {
		return nil
	}

	var r io.ReadSeeker
	size := int64(0)
	var modtime time.Time

	ok, err := hasTextSection(src)
	if err != nil {
		return err
	}
	// no need to strip the file if ".text" section is missing
	di.stripDebuginfos = ok

	if di.stripDebuginfos {
		if err := os.MkdirAll(di.tempDir, 0o755); err != nil {
			return fmt.Errorf("failed to create temp dir: %w", err)
		}
		f, err := os.CreateTemp(di.tempDir, buildID)
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(f.Name())

		if err := di.Extract(ctx, f, src); err != nil {
			return fmt.Errorf("failed to extract debug information: %w", err)
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to the beginning of the file: %w", err)
		}
		if err := validate(f); err != nil {
			return fmt.Errorf("failed to validate debug information: %w", err)
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to the beginning of the file: %w", err)
		}

		stat, err := f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat the file: %w", err)
		}
		size = stat.Size()
		modtime = stat.ModTime()

		r = f
	} else {
		f, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("failed to open debug information: %w", err)
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat the file: %w", err)
		}
		size = stat.Size()
		modtime = stat.ModTime()

		r = f
	}

	// The hash is cached to avoid re-hashing the same binary
	// and getting to the same result again.
	var (
		key = hashCacheKey{
			buildID: buildID,
			modtime: modtime.Unix(),
		}
		h string
	)
	if v, ok := di.hashCache.Load(key); ok {
		h = v.(string) //nolint:forcetypeassert
	} else {
		h, err = hash.Reader(r)
		if err != nil {
			return fmt.Errorf("hash debuginfos: %w", err)
		}
		di.hashCache.Store(key, h)

		if _, err = r.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to the beginning of the file: %w", err)
		}
	}

	initiateResp, err := di.debuginfoClient.InitiateUpload(ctx, &debuginfopb.InitiateUploadRequest{
		BuildId: buildID,
		Hash:    h,
		Size:    size,
	})
	if err != nil {
		if sts, ok := status.FromError(err); ok {
			if sts.Code() == codes.AlreadyExists {
				di.shouldInitiateUploadResponseCache.Put(buildID, struct{}{})
				return nil
			}
		}
		return fmt.Errorf("initiate upload: %w", err)
	}

	// If we found a debuginfo file, either in file or on the system, we upload it to the server.
	if err := di.upload(ctx, initiateResp.UploadInstructions, r); err != nil {
		di.metrics.uploadFailure.Inc()
		return fmt.Errorf("upload debuginfo: %w", err)
	}

	_, err = di.debuginfoClient.MarkUploadFinished(ctx, &debuginfopb.MarkUploadFinishedRequest{
		BuildId:  buildID,
		UploadId: initiateResp.UploadInstructions.UploadId,
	})
	if err != nil {
		di.metrics.uploadFailure.Inc()
		return fmt.Errorf("mark upload finished: %w", err)
	}

	di.metrics.uploadSuccess.Inc()
	return nil
}

func (di *Manager) shouldInitiateUpload(ctx context.Context, buildID, filepath string) bool {
	if _, ok := di.shouldInitiateUploadResponseCache.GetIfPresent(buildID); ok {
		return false
	}

	shouldInitiateResp, err := di.debuginfoClient.ShouldInitiateUpload(ctx, &debuginfopb.ShouldInitiateUploadRequest{
		BuildId: buildID,
	})
	if err != nil {
		level.Error(di.logger).Log("msg", "failed to check whether build ID symbol exists", "err", err, "buildid", buildID, "filepath", filepath)
	}

	if err == nil {
		if !shouldInitiateResp.ShouldInitiateUpload {
			di.shouldInitiateUploadResponseCache.Put(buildID, struct{}{})
			return false
		}

		return true
	}

	return true
}

func (di *Manager) debuginfoSrcPath(ctx context.Context, buildID string, objFile *objectfile.MappedObjectFile) string {
	if val, ok := di.debuginfoSrcCache.GetIfPresent(buildID); ok {
		if str, ok := val.(string); !ok {
			level.Error(log.With(di.logger)).Log("msg", "failed to convert buildID cache result to string")
		} else if _, err := os.Stat(str); err == nil {
			// Return if file still exists.
			return str
		}
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

func (di *Manager) upload(ctx context.Context, uploadInstructions *debuginfopb.UploadInstructions, r io.Reader) error {
	switch uploadInstructions.UploadStrategy {
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC:
		return uploadViaGRPC(ctx, di.debuginfoClient, uploadInstructions, r)
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL:
		return uploadViaSignedURL(ctx, uploadInstructions.SignedUrl, r)
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_UNSPECIFIED:
		return fmt.Errorf("upload strategy unspecified, must set one of UPLOAD_STRATEGY_GRPC or UPLOAD_STRATEGY_SIGNED_URL")
	default:
		return fmt.Errorf("unknown upload strategy: %v", uploadInstructions.UploadStrategy)
	}
}

func uploadViaGRPC(ctx context.Context, debuginfoClient debuginfopb.DebuginfoServiceClient, uploadInstructions *debuginfopb.UploadInstructions, r io.Reader) error {
	_, err := parcadebuginfo.NewGrpcUploadClient(debuginfoClient).Upload(ctx, uploadInstructions, r)
	return err
}

func uploadViaSignedURL(ctx context.Context, url string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do upload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
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

func hasTextSection(src string) (bool, error) {
	file, err := os.Open(src)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return false, fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer elfFile.Close()

	if textSection := elfFile.Section(".text"); textSection == nil {
		return false, nil
	}
	return true, nil
}
