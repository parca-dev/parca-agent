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
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

var errNotFound = errors.New("not found")

// Manager is a mechanism for extracting or finding the relevant debug information for the discovered executables.
type Manager struct {
	logger      log.Logger
	metrics     *metrics
	objFilePool *objectfile.Pool

	debuginfoClient debuginfopb.DebuginfoServiceClient
	stripDebuginfos bool
	tempDir         string

	// hashCacheKey is used as cache key for all the caches below.
	// hashCache caches ELF hashes.
	hashCache burrow.Cache

	uploadTaskTokens *semaphore.Weighted

	// If requested buildID is not in the cache, we do NOT initiate an upload request to the server.
	shouldInitiateUploadResponseCache burrow.Cache
	// Makes sure we do not try to upload the same buildID simultaneously.
	uploadSingleflight    *singleflight.Group
	uploadRetryCount      int
	uploadTimeoutDuration time.Duration

	*Extractor
	*Finder
}

// New creates a new Manager.
func New(
	logger log.Logger,
	reg prometheus.Registerer,
	objFilePool *objectfile.Pool,
	debuginfoClient debuginfopb.DebuginfoServiceClient,
	uploadTimeout time.Duration,
	uploadRetryCount int,
	cacheTTL time.Duration,
	debugDirs []string,
	stripDebuginfos bool,
	tempDir string,
) *Manager {
	return &Manager{
		logger:      logger,
		metrics:     newMetrics(reg),
		objFilePool: objFilePool,

		debuginfoClient: debuginfoClient,
		stripDebuginfos: stripDebuginfos,
		tempDir:         tempDir,

		shouldInitiateUploadResponseCache: burrow.New(
			burrow.WithMaximumSize(512), // Arbitrary cache size.
			burrow.WithExpireAfterWrite(cacheTTL),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_initiate_upload_response")),
		),
		uploadSingleflight:    &singleflight.Group{},
		uploadRetryCount:      uploadRetryCount,
		uploadTimeoutDuration: uploadTimeout,
		uploadTaskTokens:      semaphore.NewWeighted(int64(25)), // Arbitrary number.

		hashCache: burrow.New(
			burrow.WithMaximumSize(1024), // Arbitrary cache size.
			burrow.WithExpireAfterAccess(5*time.Minute),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_hash")),
		),

		Finder:    NewFinder(logger, reg, debugDirs),
		Extractor: NewExtractor(logger),
	}
}

// hashCacheKey is a cache key to retrieve the hashes of debuginfo files.
// Caching reduces allocs by 7.22% (33 kB/operation less) in Upload,
// and it shaves 4 allocs per operation.
type hashCacheKey struct {
	buildID string
	modtime int64
}

// ExtractOrFindDebugInfo extracts or finds the debug information for the given object file.
// And sets the debuginfo file pointer to the debuginfo object file.
func (di *Manager) ExtractOrFindDebugInfo(ctx context.Context, root string, srcFile *objectfile.ObjectFile) error {
	if srcFile.DebuginfoFile != nil {
		// Already extracted.
		return nil
	}

	// First, check whether debuginfos have been installed separately,
	// typically in /usr/lib/debug, so we try to discover if there is a debuginfo file,
	// that has the same build ID as the object.
	dbgInfoPath, err := di.Find(ctx, root, srcFile)
	if err == nil && dbgInfoPath != "" {
		dbgInfoFile, err := di.objFilePool.Open(dbgInfoPath)
		if err == nil {
			srcFile.DebuginfoFile = dbgInfoFile
			return nil
		}
		level.Debug(di.logger).Log("msg", "failed to open debuginfo file", "path", dbgInfoPath, "err", err)
	}

	// If we didn't find an external debuginfo file, we continue with striping to create one.
	dbgInfoFile, err := di.stripDebuginfo(ctx, srcFile)
	if err != nil {
		return fmt.Errorf("failed to strip debuginfo: %w", err)
	}
	srcFile.DebuginfoFile = dbgInfoFile
	return nil
}

func (di *Manager) Close() error {
	var err error
	err = errors.Join(err, di.Finder.Close())
	err = errors.Join(err, di.shouldInitiateUploadResponseCache.Close())
	return err
}

func (di *Manager) stripDebuginfo(ctx context.Context, src *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	buildID := src.BuildID

	binaryHasTextSection := src.HasTextSection()

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

		debuginfoFile, err = di.objFilePool.NewFile(f)
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

func (di *Manager) UploadWithRetry(ctx context.Context, objFile *objectfile.ObjectFile) error {
	var (
		ticker = backoff.NewTicker(backoff.NewExponentialBackOff())
		err    error
		count  int
		logger = log.With(di.logger, "buildid", objFile.BuildID, "path", objFile.Path)
	)
	for range ticker.C {
		if count >= di.uploadRetryCount {
			err = fmt.Errorf("upload retry count exceeded: %d", count)
			break
		}
		if err = di.Upload(ctx, objFile); err != nil {
			level.Debug(logger).Log("msg", "failed to upload debuginfo file", "err", err)
			continue
		}
		ticker.Stop()
		break
	}
	return err
}

func (di *Manager) Upload(ctx context.Context, objFile *objectfile.ObjectFile) error {
	ctx, cancel := context.WithTimeout(ctx, di.uploadTimeoutDuration)
	defer cancel()

	var (
		dbgFile = objFile.DebuginfoFile
		buildID = dbgFile.BuildID
		logger  = log.With(di.logger, "buildid", objFile.BuildID, "path", objFile.Path)
	)

	var errCh chan error
	go func() {
		defer close(errCh)

		// Acquire a token to limit the number of concurrent uploads.
		if err := di.uploadTaskTokens.Acquire(ctx, 1); err != nil {
			errCh <- fmt.Errorf("failed to acquire upload task token: %w", err)
			return
		}
		defer di.uploadTaskTokens.Release(1)

		// The singleflight group prevents uploading the same buildID concurrently.
		_, err, shared := di.uploadSingleflight.Do(buildID, func() (interface{}, error) {
			return nil, di.upload(ctx, objFile)
		})
		if shared {
			level.Debug(logger).Log("msg", "debuginfo file is being uploaded by another goroutine")
		}
		errCh <- err
	}()
	return <-errCh
}

func (di *Manager) upload(ctx context.Context, dbgFile *objectfile.ObjectFile) error {
	buildID := dbgFile.BuildID
	if shouldInitiateUpload := di.shouldInitiateUpload(ctx, buildID, dbgFile.Path); !shouldInitiateUpload {
		return nil
	}

	var (
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
	if v, ok := di.hashCache.GetIfPresent(key); ok {
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
		di.hashCache.Put(key, h)

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
