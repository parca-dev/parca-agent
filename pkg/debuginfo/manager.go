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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

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
	uploadMaxParallel int,
	uploadTimeout time.Duration,
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
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_upload_initiate")),
		),
		uploadSingleflight:    &singleflight.Group{},
		uploadTimeoutDuration: uploadTimeout,
		uploadTaskTokens:      semaphore.NewWeighted(int64(uploadMaxParallel)),

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
func (di *Manager) ExtractOrFindDebugInfo(ctx context.Context, root string, srcFile *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	// First, check whether debuginfos have been installed separately,
	// typically in /usr/lib/debug, so we try to discover if there is a debuginfo file,
	// that has the same build ID as the object.
	now := time.Now()
	dbgInfoPath, err := di.Find(ctx, root, srcFile)
	if err == nil && dbgInfoPath != "" {
		di.metrics.find.WithLabelValues(lvSuccess).Inc()
		di.metrics.findDuration.Observe(time.Since(now).Seconds())
		dbgInfoFile, err := di.objFilePool.Open(dbgInfoPath)
		if err == nil {
			return dbgInfoFile, nil
		}
		level.Debug(di.logger).Log("msg", "failed to open debuginfo file", "path", dbgInfoPath, "err", err)
	} else {
		di.metrics.find.WithLabelValues(lvFail).Inc()
	}

	// If we didn't find an external debuginfo file, we continue with striping to create one.
	dbgInfoFile, err := di.extractDebuginfo(ctx, srcFile)
	if err != nil {
		return nil, fmt.Errorf("failed to strip debuginfo: %w", err)
	}

	return dbgInfoFile, nil
}

func (di *Manager) Close() error {
	var err error
	err = errors.Join(err, di.Finder.Close())
	err = errors.Join(err, di.shouldInitiateUploadResponseCache.Close())
	return err
}

func (di *Manager) extractDebuginfo(ctx context.Context, src *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	var (
		buildID              = src.BuildID
		binaryHasTextSection = src.HasTextSection()
		debuginfoFile        *objectfile.ObjectFile
	)

	// Only strip the `.text` section if it's present *and* stripping is enabled.
	if di.stripDebuginfos && binaryHasTextSection {
		now := time.Now()

		if err := os.MkdirAll(di.tempDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		f, err := os.CreateTemp(di.tempDir, buildID)
		if err != nil {
			di.metrics.extract.WithLabelValues(lvFail).Inc()
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		// This works because CreateTemp opened a file descriptor and linux keeps a reference count to open
		// files and won't delete them until the ref count is zero.
		defer os.Remove(f.Name())

		r, done, err := src.Reader()
		if err != nil {
			di.metrics.extract.WithLabelValues(lvFail).Inc()
			return nil, fmt.Errorf("failed to obtain reader for object file: %w", err)
		}

		if err := Extract(ctx, f, r); err != nil {
			di.metrics.extract.WithLabelValues(lvFail).Inc()
			if err := done(); err != nil {
				return nil, fmt.Errorf("failed to reporting done: %w", err)
			}
			return nil, fmt.Errorf("failed to extract debug information: %w", err)
		}
		if err := done(); err != nil {
			return nil, fmt.Errorf("failed to reporting done: %w", err)
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			di.metrics.extract.WithLabelValues(lvFail).Inc()
			return nil, fmt.Errorf("failed to seek to the beginning of the file: %w", err)
		}

		// Try to open the file to make sure it's valid.
		debuginfoFile, err = di.objFilePool.NewFile(f)
		if err != nil {
			di.metrics.extract.WithLabelValues(lvFail).Inc()
			return nil, fmt.Errorf("failed to open debuginfo file: %w", err)
		}

		di.metrics.extract.WithLabelValues(lvSuccess).Inc()
		di.metrics.extractDuration.Observe(time.Since(now).Seconds())
	} else {
		debuginfoFile = src
	}

	return debuginfoFile, nil
}

func (di *Manager) Upload(ctx context.Context, dbgFile *objectfile.ObjectFile) error {
	di.metrics.uploadRequests.Inc()

	ctx, cancel := context.WithTimeout(ctx, di.uploadTimeoutDuration)
	defer cancel()

	var (
		buildID = dbgFile.BuildID
		logger  = log.With(di.logger, "buildid", dbgFile.BuildID, "path", dbgFile.Path)
	)

	errCh := make(chan error)
	go func() {
		defer close(errCh)

		now := time.Now()
		// Acquire a token to limit the number of concurrent uploads.
		if err := di.uploadTaskTokens.Acquire(ctx, 1); err != nil {
			errCh <- fmt.Errorf("failed to acquire upload task token: %w", err)
			return
		}
		di.metrics.uploadInflight.Inc()
		// Observe the time it took to acquire the token.
		di.metrics.uploadRequestWaitDuration.Observe(time.Since(now).Seconds())

		// Release the token when the upload is done.
		defer func() {
			di.uploadTaskTokens.Release(1)
			di.metrics.uploadInflight.Dec()
		}()

		now = time.Now()
		// The singleflight group prevents uploading the same buildID concurrently.
		_, err, shared := di.uploadSingleflight.Do(buildID, func() (interface{}, error) {
			return nil, di.upload(ctx, dbgFile)
		})
		if shared {
			di.metrics.upload.WithLabelValues(lvShared).Inc()
			level.Debug(logger).Log("msg", "debuginfo file was being uploaded by another goroutine")
		}
		if err != nil {
			di.uploadSingleflight.Forget(buildID) // Do not cache failed uploads.
			di.metrics.upload.WithLabelValues(lvFail).Inc()
			errCh <- err
			return
		}
		di.metrics.upload.WithLabelValues(lvSuccess).Inc()
		di.metrics.uploadDuration.Observe(time.Since(now).Seconds())
		errCh <- nil
	}()
	return <-errCh
}

func (di *Manager) upload(ctx context.Context, dbgFile *objectfile.ObjectFile) error {
	buildID := dbgFile.BuildID
	if shouldInitiateUpload := di.shouldInitiateUpload(ctx, buildID, dbgFile.Path); !shouldInitiateUpload {
		return nil
	}

	di.metrics.uploadAttempts.Inc()
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
		r, done, err := dbgFile.Reader()
		if err != nil {
			return fmt.Errorf("failed to obtain reader for object file: %w", err)
		}

		h, err = hash.Reader(r)
		if err != nil {
			if err := done(); err != nil {
				return fmt.Errorf("failed to reporting done: %w", err)
			}
			return fmt.Errorf("hash debuginfos: %w", err)
		}
		if err := done(); err != nil {
			return fmt.Errorf("failed to reporting done: %w", err)
		}
		di.hashCache.Put(key, h)
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

	r, done, err := dbgFile.Reader()
	if err != nil {
		return fmt.Errorf("failed to obtain reader for object file: %w", err)
	}

	// If we found a debuginfo file, either in file or on the system, we upload it to the server.
	if err := di.uploadFile(ctx, initiateResp.UploadInstructions, r, size); err != nil {
		if err := done(); err != nil {
			return fmt.Errorf("failed to reporting done: %w", err)
		}
		return fmt.Errorf("upload debuginfo: %w", err)
	}
	if err := done(); err != nil {
		return fmt.Errorf("failed to reporting done: %w", err)
	}

	_, err = di.debuginfoClient.MarkUploadFinished(ctx, &debuginfopb.MarkUploadFinishedRequest{
		BuildId:  buildID,
		UploadId: initiateResp.UploadInstructions.UploadId,
	})
	if err != nil {
		return fmt.Errorf("mark upload finished: %w", err)
	}
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
	// NewGrpcUploadClient using bufio.NewReader to avoid closing the reader.
	_, err := parcadebuginfo.NewGrpcUploadClient(debuginfoClient).Upload(ctx, uploadInstructions, r)
	return err
}

func uploadViaSignedURL(ctx context.Context, url string, r io.Reader, size int64) error {
	// Client is closing the reader if the reader is also closer.
	// We need to wrap the reader to avoid this.
	// We want to have total control over the reader.
	r = bufio.NewReader(r)
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

	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, msg: %s", resp.StatusCode, string(data))
	}

	return nil
}
