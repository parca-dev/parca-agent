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
	"debug/elf"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/cache"
	parcahttp "github.com/parca-dev/parca-agent/pkg/http"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
)

type Cache[K comparable, V any] interface {
	Add(K, V)
	Get(K) (V, bool)
	Purge()
	Close() error
}

// Manager is a mechanism for extracting or finding the relevant debug information for the discovered executables.
type Manager struct {
	logger  log.Logger
	tp      trace.TracerProvider
	tracer  trace.Tracer
	metrics *metrics

	objFilePool *objectfile.Pool

	debuginfoClient debuginfopb.DebuginfoServiceClient
	stripDebuginfos bool
	tempDir         string

	// hashCacheKey is used as cache key for all the caches below.
	// hashCache caches ELF hashes.
	hashCache Cache[hashCacheKey, hashCacheValue]

	extractSingleflight    *singleflight.Group
	extractTimeoutDuration time.Duration

	// Makes sure we do not try to upload the same buildID simultaneously.
	uploadSingleflight    *singleflight.Group
	uploadTaskTokens      *semaphore.Weighted
	uploadTimeoutDuration time.Duration

	httpClient *http.Client

	*Extractor
	*Finder
}

// New creates a new Manager.
func New(
	logger log.Logger,
	tp trace.TracerProvider,
	reg prometheus.Registerer,
	objFilePool *objectfile.Pool,
	debuginfoClient debuginfopb.DebuginfoServiceClient,
	uploadMaxParallel int,
	uploadTimeout time.Duration,
	cachingDisabled bool,
	debugDirs []string,
	stripDebuginfos bool,
	tempDir string,
) *Manager {
	var hashCache Cache[hashCacheKey, hashCacheValue] = cache.NewNoopCache[hashCacheKey, hashCacheValue]()
	if !cachingDisabled {
		hashCache = cache.NewLRUCacheWithTTL[hashCacheKey, hashCacheValue](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "debuginfo_hash"}, reg),
			1024,
			5*time.Minute,
		)
	}
	tracer := tp.Tracer("debuginfo")
	return &Manager{
		logger:      logger,
		tp:          tp,
		tracer:      tracer,
		metrics:     newMetrics(reg),
		objFilePool: objFilePool,

		debuginfoClient: debuginfoClient,
		stripDebuginfos: stripDebuginfos,
		tempDir:         tempDir,

		httpClient: parcahttp.NewClient(reg),
		Extractor:  NewExtractor(logger, tracer),
		Finder:     NewFinder(logger, tracer, reg, debugDirs),

		hashCache: hashCache,

		extractSingleflight:    &singleflight.Group{},
		extractTimeoutDuration: uploadTimeout / 2,

		uploadSingleflight:    &singleflight.Group{},
		uploadTaskTokens:      semaphore.NewWeighted(int64(uploadMaxParallel)),
		uploadTimeoutDuration: uploadTimeout,
	}
}

// hashCacheKey is a cache key to retrieve the hashes of debuginfo files.
// Caching reduces allocs by 7.22% (33 kB/operation less) in Upload,
// and it shaves 4 allocs per operation.
type hashCacheKey struct {
	buildID string
	modtime int64
}

type hashCacheValue struct {
	hash string
}

// UploadMapping uploads that the debuginfo file associated (found or extracted) with the given mapping has been uploaded to the server.
// If the debuginfo file has not been uploaded yet, it will be uploaded.
func (di *Manager) UploadMapping(ctx context.Context, m *process.Mapping) (err error) { //nolint:nonamedreturns
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.EnsureUploaded")
	defer span.End()

	// ObjectFile should be cached in the pool by this point.
	src, err := di.objFilePool.Open(m.AbsolutePath())
	if err != nil {
		return fmt.Errorf("failed to open object file: %w", err)
	}

	span.SetAttributes(
		attribute.Int("pid", m.PID),
		attribute.String("buildid", src.BuildID),
		attribute.String("path", src.Path),
	)

	defer func() {
		if err != nil {
			di.metrics.ensureUploadedRequests.WithLabelValues(lvFail).Inc()
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, err.Error())
			return
		}
		di.metrics.ensureUploadedRequests.WithLabelValues(lvSuccess).Inc()
	}()

	var dbg *objectfile.ObjectFile
	if src.DebugFile != nil {
		// If the debuginfo file is already extracted or found, we do not need to do it again.
		// We just need to make sure it is uploaded.
		dbg = src.DebugFile
	} else {
		// We upload the debug information files asynchronous and concurrently with retry.
		// However, first we need to find the debuginfo file or extract debuginfo from the executable.
		// For the short-lived processes, we may not complete the operation before the process exits.
		// Therefore, to be able shorten this window as much as possible, we extract and find the debuginfo
		// files synchronously and upload them asynchronously.
		// We still might be too slow to obtain the necessary file descriptors for certain short-lived processes.
		if dbg, err = di.ExtractOrFind(ctx, m.Root(), src); err != nil {
			di.metrics.ensureUploadedErrors.WithLabelValues(lvExtractOrFind).Inc()
			return err
		}
		src.DebugFile = dbg
	}

	// NOTICE: All the caches and references are based on the source file's buildID.
	// Extraction won't change the buildID, but finding might.
	// This is not a problem, Find has its own cache and it will be bounced back from server upload step.
	if err := di.Upload(ctx, dbg); err != nil {
		di.metrics.ensureUploadedErrors.WithLabelValues(lvUpload).Inc()
		return err
	}
	return nil
}

// ShouldInitiateUpload checks whether the debuginfo file associated with the given buildID should be uploaded.
// If the buildID is already in the cache, there is no need to extract, find or upload the debuginfo file.
func (di *Manager) ShouldInitiateUpload(ctx context.Context, buildID string) (_ bool, err error) { //nolint:nonamedreturns
	if err = ctx.Err(); err != nil {
		return
	}

	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.ShouldInitiateUpload")
	defer span.End()

	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, err.Error())
		}
	}()

	shouldInitiateResp, err := di.debuginfoClient.ShouldInitiateUpload(ctx, &debuginfopb.ShouldInitiateUploadRequest{
		BuildId: buildID,
	})
	if err != nil {
		return false, err
	}

	if !shouldInitiateResp.ShouldInitiateUpload {
		return false, nil
	}

	return true, nil
}

// ExtractOrFind extracts or finds the debug information for the given object file.
// And sets the debuginfo file pointer to the debuginfo object file.
func (di *Manager) ExtractOrFind(ctx context.Context, root string, src *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.ExtractOrFind")
	defer span.End()

	// First, check whether debuginfos have been installed separately,
	// typically in /usr/lib/debug, so we try to discover if there is a debuginfo file,
	// that has the same build ID as the object.
	now := time.Now()
	dbgInfoPath, err := di.Finder.Find(ctx, root, src)
	if err == nil && dbgInfoPath != "" {
		di.metrics.found.WithLabelValues(lvSuccess).Inc()
		di.metrics.findDuration.Observe(time.Since(now).Seconds())
		dbgInfoFile, err := di.objFilePool.Open(dbgInfoPath)
		if err == nil {
			return dbgInfoFile, nil
		}

		level.Debug(di.logger).Log("msg", "failed to open FOUND debuginfo file", "path", dbgInfoPath, "err", err)
	} else {
		di.metrics.found.WithLabelValues(lvFail).Inc()
	}

	// If we didn't find an external debuginfo file, we continue with striping to create one.
	dbgInfoFile, err := di.Extract(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("failed to strip debuginfo: %w", err)
	}

	return dbgInfoFile, nil
}

func (di *Manager) Extract(ctx context.Context, src *objectfile.ObjectFile) (*objectfile.ObjectFile, error) {
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.Extract")
	defer span.End()

	buildID := src.BuildID

	ef, err := src.ELF()
	if err != nil {
		return nil, fmt.Errorf("failed to get ELF file: %w", err)
	}
	binaryHasTextSection := hasTextSection(ef)

	// Only strip the `.text` section if it's present *and* stripping is enabled.
	if di.stripDebuginfos && binaryHasTextSection {
		val, err, shared := di.extractSingleflight.Do(buildID, func() (interface{}, error) {
			ctx, cancel := context.WithTimeout(ctx, di.extractTimeoutDuration)
			defer cancel()

			return di.extract(ctx, buildID, src)
		})
		if err != nil {
			if shared {
				di.extractSingleflight.Forget(buildID)
			}
			return nil, err
		}

		dbg, ok := val.(*objectfile.ObjectFile)
		if !ok {
			return nil, fmt.Errorf("unexpected type returned: %T", val)
		}
		return dbg, err
	}

	return src, nil
}

func (di *Manager) extract(ctx context.Context, buildID string, src *objectfile.ObjectFile) (_ *objectfile.ObjectFile, err error) { //nolint:nonamedreturns
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.extract")
	defer span.End()

	now := time.Now()
	defer func() {
		if err != nil {
			di.metrics.extracted.WithLabelValues(lvFail).Inc()
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, err.Error())
			return
		}
		di.metrics.extracted.WithLabelValues(lvSuccess).Inc()
		di.metrics.extractDuration.Observe(time.Since(now).Seconds())
	}()

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

	span.AddEvent("acquiring reader for objectfile")
	r, err := src.Reader()
	if err != nil {
		err = fmt.Errorf("failed to obtain reader for object file: %w", err)
		return nil, err
	}
	span.AddEvent("acquired reader for objectfile")

	if err := di.Extractor.Extract(ctx, f, r); err != nil {
		err = fmt.Errorf("failed to extract debug information: %w", err)
		return nil, err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to the beginning of the file: %w", err)
	}

	// Try to open the file to make sure it's valid.
	debuginfoFile, err := di.objFilePool.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to open debuginfo file: %w", err)
	}
	return debuginfoFile, nil
}

func (di *Manager) Upload(ctx context.Context, dbg *objectfile.ObjectFile) (err error) { //nolint:nonamedreturns
	di.metrics.uploadRequests.Inc()

	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.Upload")
	defer span.End()

	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, err.Error())
		}
	}()

	buildID := dbg.BuildID

	now := time.Now()
	span.AddEvent("acquiring upload task token")
	// Acquire a token to limit the number of concurrent uploads.
	if err := di.uploadTaskTokens.Acquire(ctx, 1); err != nil {
		return fmt.Errorf("failed to acquire upload task token: %w", err)
	}
	di.metrics.uploadInflight.Inc()
	// Observe the time it took to acquire the token.
	di.metrics.uploadRequestWaitDuration.Observe(time.Since(now).Seconds())
	span.AddEvent("acquired upload task token")

	// Release the token when the upload is done.
	defer func() {
		di.uploadTaskTokens.Release(1)
		di.metrics.uploadInflight.Dec()
	}()

	now = time.Now()
	// The singleflight group prevents uploading the same buildID concurrently.
	_, err, shared := di.uploadSingleflight.Do(buildID, func() (interface{}, error) {
		return nil, di.upload(ctx, dbg)
	})
	if shared {
		di.metrics.uploaded.WithLabelValues(lvShared).Inc()
		span.SetAttributes(attribute.Bool("shared", true))
	}
	if err != nil {
		di.uploadSingleflight.Forget(buildID) // Do not cache failed uploads.
		di.metrics.uploaded.WithLabelValues(lvFail).Inc()
		return err
	}
	di.metrics.uploaded.WithLabelValues(lvSuccess).Inc()
	di.metrics.uploadDuration.Observe(time.Since(now).Seconds())
	return nil
}

func (di *Manager) upload(ctx context.Context, dbg *objectfile.ObjectFile) (err error) { //nolint:nonamedreturns
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.upload")
	defer span.End()

	buildID := dbg.BuildID
	if shouldInitiateUpload, _ := di.ShouldInitiateUpload(ctx, buildID); !shouldInitiateUpload {
		return nil
	}

	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, err.Error())
			return
		}
	}()

	di.metrics.uploadAttempts.Inc()

	var (
		// The hash is cached to avoid re-hashing the same binary
		// and getting to the same result again.
		key = hashCacheKey{
			buildID: buildID,
			modtime: dbg.Modtime.Unix(),
		}
		size = dbg.Size
		h    string
	)
	if v, ok := di.hashCache.Get(key); ok {
		h = v.hash
	} else {
		span.AddEvent("acquiring reader for objectfile")
		r, err := dbg.Reader()
		if err != nil {
			return fmt.Errorf("failed to obtain reader for object file: %w", err)
		}
		span.AddEvent("acquired reader for objectfile")

		h, err = hash.Reader(r)
		if err != nil {
			return fmt.Errorf("hash debuginfos: %w", err)
		}
		di.hashCache.Add(key, hashCacheValue{hash: h})
	}

	initiateResp, err := di.debuginfoClient.InitiateUpload(ctx, &debuginfopb.InitiateUploadRequest{
		BuildId: buildID,
		Hash:    h,
		Size:    size,
	})
	if err != nil {
		if sts, ok := status.FromError(err); ok {
			if sts.Code() == codes.AlreadyExists {
				return nil
			}
		}
		return fmt.Errorf("initiate upload: %w", err)
	}

	di.metrics.uploadInitiated.Inc()

	span.AddEvent("acquiring reader for objectfile")
	r, err := dbg.Reader()
	if err != nil {
		return fmt.Errorf("failed to obtain reader for object file: %w", err)
	}
	span.AddEvent("acquired reader for objectfile")

	// If we found a debuginfo file, either in file or on the system, we upload it to the server.
	if err := di.uploadFile(ctx, initiateResp.UploadInstructions, r, size); err != nil {
		err = fmt.Errorf("upload debuginfo: %w", err)
		return err
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

func (di *Manager) uploadFile(ctx context.Context, uploadInstructions *debuginfopb.UploadInstructions, r io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, di.uploadTimeoutDuration)
	defer cancel()

	switch uploadInstructions.UploadStrategy {
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC:
		return di.uploadViaGRPC(ctx, di.debuginfoClient, uploadInstructions, r)
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL:
		return di.uploadViaSignedURL(ctx, uploadInstructions.SignedUrl, r, size)
	case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_UNSPECIFIED:
		return fmt.Errorf("upload strategy unspecified, must set one of UPLOAD_STRATEGY_GRPC or UPLOAD_STRATEGY_SIGNED_URL")
	default:
		return fmt.Errorf("unknown upload strategy: %v", uploadInstructions.UploadStrategy)
	}
}

func (di *Manager) uploadViaGRPC(ctx context.Context, debuginfoClient debuginfopb.DebuginfoServiceClient, uploadInstructions *debuginfopb.UploadInstructions, r io.Reader) error {
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.uploadViaGRPC")
	defer span.End()

	// NewGrpcUploadClient using bufio.NewReader to avoid closing the reader.
	_, err := parcadebuginfo.NewGrpcUploadClient(debuginfoClient).Upload(ctx, uploadInstructions, r)
	return err
}

func (di *Manager) uploadViaSignedURL(ctx context.Context, url string, r io.Reader, size int64) error {
	ctx, span := di.tracer.Start(ctx, "DebuginfoManager.uploadViaSignedURL")
	defer span.End()

	// Client is closing the reader if the reader is also closer.
	// We need to wrap the reader to avoid this.
	// We want to have total control over the reader.
	r = bufio.NewReader(r)
	ctx = httptrace.WithClientTrace(ctx, otelhttptrace.NewClientTrace(ctx, otelhttptrace.WithTracerProvider(di.tp)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.ContentLength = size
	resp, err := di.httpClient.Do(req)
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

func (di *Manager) Close() error {
	return di.Finder.Close()
}

// hasTextSection returns true if the ELF file has a .text section.
func hasTextSection(ef *elf.File) bool {
	if textSection := ef.Section(".text"); textSection == nil {
		return false
	}
	return true
}
