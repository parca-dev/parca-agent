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
	burrow "github.com/goburrow/cache"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var errNotFound = errors.New("not found")

// Manager is a mechanism for extracting or finding the relevant debug information for the discovered executables.
type Manager struct {
	logger          log.Logger
	metrics         *metrics
	debuginfoClient debuginfopb.DebuginfoServiceClient

	stripDebuginfos bool
	tempDir         string

	// hashCache caches ELF hashes (hashCacheKey is a key).
	hashCache                         *sync.Map
	shouldInitiateUploadResponseCache burrow.Cache

	// Make sure we only upload one debuginfo file at a time per build ID.
	uploadSingleflight singleflight.Group
	// TODO(kakkoyun): ?!
	// extractSingleflight singleflight.Group

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

		shouldInitiateUploadResponseCache: burrow.New(
			burrow.WithMaximumSize(512), // Arbitrary cache size.
			burrow.WithExpireAfterWrite(cacheTTL),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_initiate_upload_response")),
		),
		hashCache: &sync.Map{},
		// uploadingCache: burrow.New(
		// 	burrow.WithMaximumSize(1024),
		// 	burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_uploading")),
		// ),
		Finder:    NewFinder(logger, reg, debugDirs),
		Extractor: NewExtractor(logger),

		stripDebuginfos: stripDebuginfos,
		tempDir:         tempDir,

		uploadTimeoutDuration: uploadTimeout,
	}
}

// hashCacheKey is a cache key to retrieve the hashes of debuginfo files.
// Caching reduces allocs by 7.22% (33 kB/operation less) in ensureUpload,
// and it shaves 4 allocs per operation.
type hashCacheKey struct {
	buildID string
	modtime int64
}

func (di *Manager) ExtractOrFindDebugInfo(ctx context.Context, root string, objFile *objectfile.ObjectFile) error {
	// TODO(kakkoyun): Could this ever happen?
	// - Maybe with a global ObjectFile cache?
	// - We need a global cache for the debuginfo files per build ID.
	if objFile.DebuginfoFile != nil {
		// Already extracted.
		return nil
	}

	var srcFile *objectfile.ObjectFile
	// First, check whether debuginfos have been installed separately,
	// typically in /usr/lib/debug, so we try to discover if there is a debuginfo file,
	// that has the same build ID as the object.
	dbgInfoPath, err := di.Find(ctx, root, objFile)
	if err == nil && dbgInfoPath != "" {
		srcFile, err = objectfile.Open(dbgInfoPath)
		if err != nil {
			level.Debug(di.logger).Log("msg", "failed to open debuginfo file", "path", dbgInfoPath, "err", err)
		}
	}

	// If we didn't find a debuginfo file, we continue with the object file.
	if srcFile == nil {
		srcFile = objFile
	}

	debuginfoFile, err := di.stripDebuginfo(ctx, srcFile)
	if err != nil {
		return fmt.Errorf("failed to strip debuginfo: %w", err)
	}
	objFile.DebuginfoFile = debuginfoFile

	return nil
}

func (di *Manager) stripDebuginfo(ctx context.Context, src *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	buildID := src.BuildID

	binaryHasTextSection, err := hasTextSection(src.ElfFile)
	if err != nil {
		return nil, err
	}
	if err := src.Rewind(); err != nil {
		return nil, fmt.Errorf("failed to rewind debuginfo file: %w", err)
	}

	var debuginfoFile *objectfile.ObjectFile

	// Only strip the `.text` section if it's present *and* stripping is enabled.
	if di.stripDebuginfos && binaryHasTextSection {
		if err := os.MkdirAll(di.tempDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		f, err := os.CreateTemp(di.tempDir, buildID)
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		// This works because CreateTemp opened a file descriptor and linux keeps a reference count to open
		// files and won't delete them until the ref count is zero.
		defer os.Remove(f.Name())

		if err := Extract(ctx, f, src.File); err != nil {
			return nil, fmt.Errorf("failed to extract debug information: %w", err)
		}
		if err := src.Rewind(); err != nil {
			return nil, fmt.Errorf("failed to rewind debuginfo file: %w", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to the beginning of the file: %w", err)
		}
		if err := validate(f); err != nil {
			return nil, fmt.Errorf("failed to validate debug information: %w", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to the beginning of the file: %w", err)
		}

		debuginfoFile, err = objectfile.NewFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to open debuginfo file: %w", err)
		}
	} else {
		debuginfoFile = src
	}

	return debuginfoFile, nil
}

// TODO(kakkoyun): Consider moving to object file.
func validate(f io.ReaderAt) error {
	elfFile, err := elf.NewFile(f)
	if err != nil {
		return err
	}
	// Do NOT close, we are closing it elsewhere.
	// But it should not be set anyways :)

	if len(elfFile.Sections) == 0 {
		return errors.New("ELF does not have any sections")
	}
	return nil
}

// TODO(kakkoyun): Consider moving to object file.
func hasTextSection(ef *elf.File) (bool, error) {
	if textSection := ef.Section(".text"); textSection == nil {
		return false, nil
	}
	return true, nil
}

func (di *Manager) Upload(ctx context.Context, objFile *objectfile.ObjectFile) error {
	ctx, cancel := context.WithTimeout(ctx, di.uploadTimeoutDuration)
	defer cancel()

	// The singleflight group prevents uploading the same buildID concurrently.
	buildID := objFile.BuildID
	_, err, shared := di.uploadSingleflight.Do(buildID, func() (interface{}, error) {
		if err := di.upload(ctx, objFile); err != nil {
			return nil, err
		}

		return nil, nil
	})
	defer di.uploadSingleflight.Forget(buildID)

	if shared {
		level.Debug(di.logger).Log("msg", "debuginfo file is being uploaded by another goroutine", "build_id", buildID)
	}
	return err
}

func (di *Manager) upload(ctx context.Context, objFile *objectfile.ObjectFile) error {
	buildID := objFile.BuildID

	if shouldInitiateUpload := di.shouldInitiateUpload(ctx, buildID, objFile.Path); !shouldInitiateUpload {
		return nil
	}

	var (
		dbgFile = objFile.DebuginfoFile
		// The hash is cached to avoid re-hashing the same binary
		// and getting to the same result again.
		key = hashCacheKey{
			buildID: buildID,
			modtime: dbgFile.Modtime.Unix(),
		}
		size = dbgFile.Size
		h    string
		err  error
	)
	if v, ok := di.hashCache.Load(key); ok {
		h = v.(string) //nolint:forcetypeassert
	} else {
		// TODO(kakkoyun): Is this necessary?
		if err := dbgFile.Rewind(); err != nil {
			return fmt.Errorf("failed to rewind the file: %w", err)
		}
		h, err = hash.Reader(dbgFile.File)
		if err != nil {
			return fmt.Errorf("hash debuginfos: %w", err)
		}
		di.hashCache.Store(key, h)

		if err := dbgFile.Rewind(); err != nil {
			return fmt.Errorf("failed to rewind the file: %w", err)
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
	if err := di.uploadFile(ctx, initiateResp.UploadInstructions, dbgFile.File, size); err != nil {
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

func (di *Manager) uploadFile(ctx context.Context, uploadInstructions *debuginfopb.UploadInstructions, r io.Reader, size int64) error {
	switch uploadInstructions.UploadStrategy {
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC:
		return uploadViaGRPC(ctx, di.debuginfoClient, uploadInstructions, r)
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL:
		return uploadViaSignedURL(ctx, uploadInstructions.SignedUrl, r, size)
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

func uploadViaSignedURL(ctx context.Context, url string, r io.Reader, size int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.ContentLength = size
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do upload request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, msg: %s", resp.StatusCode, string(data))
	}

	return nil
}
