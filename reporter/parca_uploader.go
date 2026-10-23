package reporter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	debuginfogrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/debuginfo/v1alpha1/debuginfov1alpha1grpc"
	debuginfopb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/debuginfo/v1alpha1"
	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/util/workqueue"

	"github.com/parca-dev/parca-agent/internal/log"

	"github.com/parca-dev/parca-agent/reporter/elfwriter"
)

type uploadRequest struct {
	fileID   libpf.FileID
	fileName string
	buildID  string
	open     func() (pfelf.ReadAtCloser, error)
}

type ParcaSymbolUploader struct {
	client           debuginfogrpc.DebuginfoServiceClient
	grpcUploadClient *GrpcUploadClient
	httpClient       *http.Client

	retry *lru.SyncedLRU[libpf.FileID, struct{}]

	stripTextSection bool
	tmp              string

	queue             chan uploadRequest
	inProgressTracker *inProgressTracker
	workerNum         int

	uploadRequestBytes prometheus.Counter
}

func NewParcaSymbolUploader(
	client debuginfogrpc.DebuginfoServiceClient,
	cacheSize uint32,
	stripTextSection bool,
	queueSize uint32,
	workerNum int,
	cacheDir string,
	uploadRequestBytes prometheus.Counter,
) (*ParcaSymbolUploader, error) {
	retryCache, err := lru.NewSynced[libpf.FileID, struct{}](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	cacheDirectory := filepath.Join(cacheDir, "symuploader")
	if _, err := os.Stat(cacheDirectory); os.IsNotExist(err) {
		log.Debugf("Creating cache directory '%s'", cacheDirectory)
		if err := os.MkdirAll(cacheDirectory, os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create cache directory (%s): %s", cacheDirectory, err)
		}
	}

	if err := filepath.Walk(cacheDirectory, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if os.Remove(path) != nil {
			log.Warnf("Failed to remove cached file: %s", path)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to clean cache directory (%s): %s", cacheDirectory, err)
	}

	return &ParcaSymbolUploader{
		httpClient:         http.DefaultClient,
		client:             client,
		grpcUploadClient:   NewGrpcUploadClient(client),
		retry:              retryCache,
		stripTextSection:   stripTextSection,
		tmp:                cacheDirectory,
		queue:              make(chan uploadRequest, queueSize),
		inProgressTracker:  newInProgressTracker(0.2, int(cacheSize)),
		workerNum:          workerNum,
		uploadRequestBytes: uploadRequestBytes,
	}, nil
}

const (
	ReasonUploadInProgress = "A previous upload is still in-progress and not stale yet (only stale uploads can be retried)."
	uploadRetryDelay       = 5 * time.Minute
)

var errUploadRetryRequired = errors.New("upload retry required")

// inProgressTracker is a simple in-progress tracker that keeps track of which
// fileIDs are currently queued, uploading, or waiting for a retry.
type inProgressTracker struct {
	mu    sync.Mutex
	m     map[libpf.FileID]struct{}
	limit int

	// tracking metadata to know when to shrink the map as otherwise the map
	// may grow indefinitely.
	maxSizeSeen      int
	shrinkLimitRatio float64
}

// newInProgressTracker returns a new in-progress tracker that shrinks the
// tracking map when the maximum size seen is larger than the current size by
// the shrinkLimitRatio.
func newInProgressTracker(shrinkLimitRatio float64, limit int) *inProgressTracker {
	return &inProgressTracker{
		m:                make(map[libpf.FileID]struct{}),
		limit:            limit,
		shrinkLimitRatio: shrinkLimitRatio,
	}
}

// TryAdd reserves a fileID unless it is already tracked or the tracker is full.
// The limit bounds retained requests, including those waiting for a retry.
func (i *inProgressTracker) TryAdd(fileID libpf.FileID) bool {
	i.mu.Lock()
	defer i.mu.Unlock()

	if _, exists := i.m[fileID]; exists || len(i.m) >= i.limit {
		return false
	}
	i.m[fileID] = struct{}{}

	if len(i.m) > i.maxSizeSeen {
		i.maxSizeSeen = len(i.m)
	}

	return true
}

// Remove removes the fileID from the in-progress state.
func (i *inProgressTracker) Remove(fileID libpf.FileID) {
	i.mu.Lock()
	defer i.mu.Unlock()

	delete(i.m, fileID)

	if i.shrinkLimitRatio > 0 &&
		int(float64(len(i.m))+float64(len(i.m))*i.shrinkLimitRatio) < i.maxSizeSeen {
		i.m = maps.Clone(i.m)
		i.maxSizeSeen = len(i.m)
	}
}

// Run starts the upload workers and schedules deferred attempts without holding
// a worker during the cooldown. Requests reopen their source on each attempt.
func (u *ParcaSymbolUploader) Run(ctx context.Context) error {
	var g errgroup.Group
	delayed := workqueue.NewTypedDelayingQueue[*uploadRequest]()
	g.Go(func() error {
		<-ctx.Done()
		delayed.ShutDown()
		return nil
	})
	g.Go(func() error {
		for {
			req, shutdown := delayed.Get()
			if shutdown {
				return nil
			}
			delayed.Done(req)
			select {
			case <-ctx.Done():
				u.inProgressTracker.Remove(req.fileID)
				return nil
			case u.queue <- *req:
			}
		}
	})

	for i := 0; i < u.workerNum; i++ {
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case req := <-u.queue:
					err := u.attemptUpload(ctx, req.fileID, req.fileName, req.buildID, req.open)
					if errors.Is(err, errUploadRetryRequired) && ctx.Err() == nil {
						delayed.AddAfter(&req, uploadRetryDelay)
					} else {
						u.inProgressTracker.Remove(req.fileID)
					}
					if err != nil && err != errUploadRetryRequired {
						log.Warnf("Failed to upload with fileName '%s' and buildID '%s': %v", req.fileName, req.buildID, err)
					}
				}
			}
		})
	}

	return g.Wait()
}

// Upload enqueues a file unless it is already tracked or marked not to be retried.
func (u *ParcaSymbolUploader) Upload(ctx context.Context, fileID libpf.FileID, fileName string, buildID string,
	open func() (pfelf.ReadAtCloser, error)) {
	_, ok := u.retry.Get(fileID)
	if ok {
		return
	}

	// Attempting to enqueue each fileID only once.
	if !u.inProgressTracker.TryAdd(fileID) {
		return
	}

	select {
	case <-ctx.Done():
		u.inProgressTracker.Remove(fileID)
	case u.queue <- uploadRequest{fileID: fileID, fileName: fileName, buildID: buildID, open: open}:
		// Nothing to do, we enqueued the request successfully.
	default:
		// The queue is full, we can't enqueue the request.
		u.inProgressTracker.Remove(fileID)
		log.Warnf("Failed to enqueue upload request with fileName '%s' and buildID '%s': queue is full", fileName, buildID)
	}
}

// attemptUpload attempts to upload the file with the given fileID and buildID.
func (u *ParcaSymbolUploader) attemptUpload(ctx context.Context, fileID libpf.FileID, fileName string, buildID string,
	open func() (pfelf.ReadAtCloser, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	buildIDType := debuginfopb.BuildIDType_BUILD_ID_TYPE_GNU
	if buildID == "" {
		buildIDType = debuginfopb.BuildIDType_BUILD_ID_TYPE_HASH
		buildID = fileID.StringNoQuotes()
	}

	shouldInitiateUploadResp, err := u.client.ShouldInitiateUpload(ctx, &debuginfopb.ShouldInitiateUploadRequest{
		BuildId:     buildID,
		BuildIdType: buildIDType,
		Type:        debuginfopb.DebuginfoType_DEBUGINFO_TYPE_DEBUGINFO_UNSPECIFIED,
	})
	if err != nil {
		return errors.Join(errUploadRetryRequired, err)
	}

	if !shouldInitiateUploadResp.ShouldInitiateUpload {
		// This can happen when two agents simultaneously try to upload the
		// same file. The other agent already started the upload so we don't
		// need to do it again, however the upload may fail so we should retry
		// after a while.
		if shouldInitiateUploadResp.RetryRequired || shouldInitiateUploadResp.Reason == ReasonUploadInProgress {
			return errUploadRetryRequired
		}
		u.retry.Add(fileID, struct{}{})
		return nil
	}

	var (
		r    io.ReaderAt
		size int64
	)
	if !u.stripTextSection {
		// We're not stripping the text section so we can upload the original file.
		f, err := open()
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist, likely because the process is already
				// gone.
				return nil
			}
			if err.Error() == "no backing file for anonymous memory" {
				// This is an anonymous memory mapping, it's not backed by
				// a file so we will never be able to extract debuginfo.
				u.retry.Add(fileID, struct{}{})
				return nil
			}
			return fmt.Errorf("open file: %w", err)
		}
		defer f.Close()

		size, err = readAtCloserSize(f)
		if err != nil {
			return err
		}
		if size == 0 {
			// The original file is empty no need to ever upload it.
			u.retry.Add(fileID, struct{}{})
			return nil
		}

		r = io.NewSectionReader(f, 0, size)
	} else {
		f, err := os.Create(filepath.Join(u.tmp, fileID.StringNoQuotes()))
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}
		defer os.Remove(f.Name())
		defer f.Close()

		original, err := open()
		if err != nil {
			os.Remove(f.Name())
			if os.IsNotExist(err) {
				// Original file doesn't exist the process is likely
				// already gone.
				return nil
			}
			if err.Error() == "no backing file for anonymous memory" {
				// This is an anonymous memory mapping, it's not backed by
				// a file so we will never be able to extract debuginfo.
				u.retry.Add(fileID, struct{}{})
				return nil
			}
			return fmt.Errorf("open original file: %w", err)
		}
		defer original.Close()

		if err := elfwriter.OnlyKeepDebug(f, original); err != nil {
			os.Remove(f.Name())
			// If we can't extract the debuginfo we can't upload the file.
			u.retry.Add(fileID, struct{}{})
			return fmt.Errorf("extract debuginfo: %w", err)
		}

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			os.Remove(f.Name())
			// Something is probably seriously wrong so don't retry.
			u.retry.Add(fileID, struct{}{})
			return fmt.Errorf("seek extracted debuginfo to start: %w", err)
		}

		stat, err := f.Stat()
		if err != nil {
			os.Remove(f.Name())
			// Something is probably seriously wrong so don't retry.
			u.retry.Add(fileID, struct{}{})
			return fmt.Errorf("stat file to upload: %w", err)
		}
		size = stat.Size()

		if size == 0 {
			os.Remove(f.Name())
			// Extraction is a deterministic process so if the file is empty we
			// will never be able to extract non-zero debuginfo the original
			// binary.
			u.retry.Add(fileID, struct{}{})
			return nil
		}

		r = f
	}

	log.Infof("Attempting to upload with fileName '%s' and buildID '%s'", fileName, buildID)
	if err := u.upload(ctx, &debuginfopb.InitiateUploadRequest{
		BuildId:                 buildID,
		BuildIdType:             buildIDType,
		Type:                    debuginfopb.DebuginfoType_DEBUGINFO_TYPE_DEBUGINFO_UNSPECIFIED,
		Hash:                    fileID.StringNoQuotes(),
		Size:                    size,
		SupportsMultipleUploads: true,
	}, r); err != nil {
		if err == errUploadRetryRequired {
			return err
		}
		return errors.Join(errUploadRetryRequired, err)
	}

	u.retry.Add(fileID, struct{}{})
	return nil
}

// upload retains pending instructions until their transfers and completions have
// succeeded or the retry budget expires. It never re-initiates a known upload.
func (u *ParcaSymbolUploader) upload(ctx context.Context, req *debuginfopb.InitiateUploadRequest, r io.ReaderAt) error {
	type pendingUpload struct {
		instructions *debuginfopb.UploadInstructions
		transferred  bool
	}
	var pending []pendingUpload
	retryRequired := true
	var lastErr error
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Second << (attempt - 1))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		if len(pending) == 0 {
			resp, err := u.client.InitiateUpload(ctx, req)
			if err != nil {
				if status.Code(err) == codes.AlreadyExists || status.Code(err) == codes.InvalidArgument {
					// These bytes were refused permanently, not necessarily stored.
					return nil
				}
				// FailedPrecondition can mean an upload is still in progress,
				// not that the artifact is available. Keep the failure retryable.
				lastErr = err
				continue
			}

			targets := resp.UploadTargets
			if resp.UploadInstructions != nil {
				if len(targets) > 0 {
					return fmt.Errorf("server returned both legacy and multiple upload instructions")
				}
				// Older servers ignore the capability bit and return this field.
				targets = []*debuginfopb.UploadInstructions{resp.UploadInstructions}
			}
			for _, instructions := range targets {
				if instructions == nil {
					return fmt.Errorf("server returned an empty upload target")
				}
				pending = append(pending, pendingUpload{instructions: instructions})
			}
			retryRequired = resp.RetryRequired
		}

		var failures []error
		remaining := pending[:0]
		for _, target := range pending {
			instructions := target.instructions
			if !target.transferred {
				// Each destination receives the entire artifact, even after a
				// previous destination consumed or failed partway through it.
				reader := io.NewSectionReader(r, 0, req.Size)
				var uploadedBytes uint64
				var err error
				switch instructions.UploadStrategy {
				case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL:
					err = u.uploadViaSignedURL(ctx, instructions.SignedUrl, reader, req.Size)
					uploadedBytes = uint64(req.Size)
				case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC:
					uploadedBytes, err = u.grpcUploadClient.Upload(ctx, instructions, reader)
				default:
					err = fmt.Errorf("unsupported upload strategy: %v", instructions.UploadStrategy)
				}
				if err != nil {
					failures = append(failures, err)
					remaining = append(remaining, target)
					continue
				}
				u.uploadRequestBytes.Add(float64(uploadedBytes))
				target.transferred = true
			}

			_, err := u.client.MarkUploadFinished(ctx, &debuginfopb.MarkUploadFinishedRequest{
				BuildId:  instructions.BuildId,
				UploadId: instructions.UploadId,
				Type:     instructions.Type,
			})
			if err != nil {
				failures = append(failures, err)
				remaining = append(remaining, target)
			}
		}
		pending = remaining
		if len(pending) == 0 {
			if retryRequired {
				return errUploadRetryRequired
			}
			return nil
		}
		lastErr = errors.Join(failures...)
	}
	return fmt.Errorf("upload incomplete after %d attempts: %w", maxAttempts, lastErr)
}

type Stater interface {
	Stat() (os.FileInfo, error)
}

// readAtCloserSize attempts to determine the size of the reader.
func readAtCloserSize(r pfelf.ReadAtCloser) (int64, error) {
	stater, ok := r.(Stater)
	if !ok {
		log.Debugf("ReadAtCloser is not a Stater, can't determine size")
		return 0, nil
	}

	stat, err := stater.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat file to upload: %w", err)
	}

	return stat.Size(), nil
}

// uploadViaSignedURL uploads the reader to the signed URL.
func (u *ParcaSymbolUploader) uploadViaSignedURL(ctx context.Context, url string, r io.Reader, size int64) error {
	// Client is closing the reader if the reader is also closer.
	// We need to wrap the reader to avoid this.
	// We want to have total control over the reader.
	r = bufio.NewReader(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.ContentLength = size
	resp, err := u.httpClient.Do(req)
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
