// Copyright 2023 The Parca Authors
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

package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
	"github.com/puzpuzpuz/xsync/v3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/interpreter"
)

type DebuginfoManager interface {
	ShouldInitiateUpload(ctx context.Context, buildID string) (bool, error)
	UploadMapping(ctx context.Context, m *Mapping) error
	Close() error
}

// TODO: Unify PID types.
type LabelManager interface {
	Fetch(ctx context.Context, pid int) error
	LabelSet(ctx context.Context, pid int) (model.LabelSet, error)
}

type Cache[K comparable, V any] interface {
	Add(key K, value V)
	Get(key K) (V, bool)
	Peek(key K) (V, bool)
	Remove(key K)
}

const (
	lvSuccess = "success"
	lvFail    = "fail"
	lvShared  = "shared"

	lvAlreadyClosed        = "already_closed"
	lvShouldInitiateUpload = "should_initiate_upload"
	lvUnknown              = "unknown"
)

type metrics struct {
	fetchAttempts    prometheus.Counter
	fetched          *prometheus.CounterVec
	fetchDuration    prometheus.Histogram
	get              prometheus.Counter
	uploadErrors     *prometheus.CounterVec
	metadataDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		fetchAttempts: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_fetch_attempts_total",
			Help: "Total number of debug information load attempts.",
		}),
		fetched: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_fetched_total",
			Help: "Total number of debug information loads.",
		}, []string{"result"}),
		fetchDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:                        "parca_agent_process_info_fetch_duration_seconds",
			Help:                        "Duration of debug information loads.",
			NativeHistogramBucketFactor: 1.1,
		}),
		get: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_get_total",
			Help: "Total number of debug information gets.",
		}),
		uploadErrors: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_upload_errors_total",
			Help: "Total number of debug information upload errors.",
		}, []string{"type"}),
		metadataDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:                        "parca_agent_process_info_metadata_fetch_duration_seconds",
			Help:                        "Duration of metadata fetches.",
			NativeHistogramBucketFactor: 1.1,
		}),
	}
	m.fetched.WithLabelValues(lvSuccess)
	m.fetched.WithLabelValues(lvFail)
	m.fetched.WithLabelValues(lvShared)
	m.uploadErrors.WithLabelValues(lvShouldInitiateUpload)
	m.uploadErrors.WithLabelValues(lvAlreadyClosed)
	m.uploadErrors.WithLabelValues(lvUnknown)
	return m
}

type InfoManager struct {
	logger  log.Logger
	tracer  trace.Tracer
	metrics *metrics

	cache                     Cache[int, Info]
	cacheForMappings          Cache[int, uint64]
	shouldInitiateUploadCache Cache[string, struct{}]
	uploadInflight            *xsync.MapOf[string, struct{}]

	procFS           procfs.FS
	objFilePool      *objectfile.Pool
	mapManager       *MapManager
	debuginfoManager DebuginfoManager
	labelManager     LabelManager

	uploadJobQueue chan *uploadJob
	uploadJobPool  *sync.Pool

	shouldFetchInterpreterInfo bool
}

func NewInfoManager(
	logger log.Logger,
	tracer trace.Tracer,
	reg prometheus.Registerer,
	proceFS procfs.FS,
	objFilePool *objectfile.Pool,
	mm *MapManager,
	dim DebuginfoManager,
	lm LabelManager,
	profilingDuration time.Duration,
	cacheTTL time.Duration,
	fetchInterpreterInfo bool,
) *InfoManager {
	im := &InfoManager{
		logger:  logger,
		tracer:  tracer,
		metrics: newMetrics(reg),
		cache: cache.NewLRUCacheWithTTL[int, Info](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "process_info"}, reg),
			1024,
			12*profilingDuration,
			cache.CacheWithTTLOptions{
				RemoveExpiredOnAdd: true,
			},
		),
		cacheForMappings: cache.NewLRUCacheWithTTL[int, uint64](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "process_mapping_info"}, reg),
			1024,
			cacheTTL,
		),
		shouldInitiateUploadCache: cache.NewLRUCacheWithTTL[string, struct{}](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "debuginfo_should_initiate"}, reg),
			1024,
			cacheTTL,
		),
		uploadInflight:   xsync.NewMapOf[string, struct{}](),
		procFS:           proceFS,
		objFilePool:      objFilePool,
		mapManager:       mm,
		debuginfoManager: dim,
		labelManager:     lm,

		uploadJobQueue: make(chan *uploadJob, 128),
		uploadJobPool: &sync.Pool{
			New: func() interface{} {
				return &uploadJob{}
			},
		},
		shouldFetchInterpreterInfo: fetchInterpreterInfo,
	}
	return im
}

type Info struct {
	im  *InfoManager
	pid int

	// - Unwind Information
	Interpreter *runtime.Interpreter
	Mappings    Mappings
}

func (i Info) Labels(ctx context.Context) (model.LabelSet, error) {
	ctx, span := i.im.tracer.Start(ctx, "ProcessInfoManager.Info.Labels")
	defer span.End()

	// NOTICE: Caching is not necessary here since the label set is already cached in the label manager.
	return i.im.labelManager.LabelSet(ctx, i.pid)
}

func (im *InfoManager) Fetch(ctx context.Context, pid int) (Info, error) {
	im.metrics.fetchAttempts.Inc()

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Fetch")
	defer span.End()

	return im.fetch(ctx, pid, false)
}

func (im *InfoManager) FetchWithFreshMappings(ctx context.Context, pid int) (Info, error) {
	im.metrics.fetchAttempts.Inc()

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.FetchWithFreshMappings")
	defer span.End()

	return im.fetch(ctx, pid, true)
}

// Fetch collects the required information for a process and stores it for future needs.
func (im *InfoManager) fetch(ctx context.Context, pid int, checkMappings bool) (info Info, err error) { //nolint:nonamedreturns
	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	info, exists := im.cache.Peek(pid)
	if exists && !checkMappings {
		im.ensureDebuginfoUploaded(ctx, info.Mappings)
		return info, nil
	}

	// Any operation in this block will be executed only once for a given pid.
	// However, it needs to be fast as possible since it will block other goroutines.
	// And to avoid missing information for the short lived processes, the extraction and finding of debug information
	// should be done as soon as possible.

	proc, err := im.procFS.Proc(pid)
	if err != nil {
		return Info{}, fmt.Errorf("failed to open proc %d: %w", pid, err)
	}
	exe, err := proc.Executable()
	if err != nil {
		return Info{}, fmt.Errorf("failed to get executable for proc %d: %w", pid, err)
	}
	// Cache the executable path for future needs.
	path := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), exe)
	if !(strings.Contains(path, "(deleted)") || strings.Contains(path, "memfd:")) {
		if _, err = im.objFilePool.Open(path); err != nil {
			return Info{}, fmt.Errorf("failed to get executable object file for %s: %w", path, err)
		}
	}

	// Get the mappings of the process. This caches underlying object files for future needs.
	mappings, err := im.mapManager.MappingsForPID(pid)
	if err != nil {
		return Info{}, err
	}

	if checkMappings {
		// Check if the mappings are changed.
		cachedMappingsHash, exists := im.cacheForMappings.Get(pid)
		hash, err := mappings.Hash()
		if err != nil {
			return Info{}, fmt.Errorf("failed to hash mappings: %w", err)
		}
		if exists && cachedMappingsHash == hash {
			// If not, we don't need to do anything.
			return info, nil
		}
	}

	now := time.Now()
	defer func() {
		if err != nil {
			im.metrics.fetched.WithLabelValues(lvFail).Inc()
		} else {
			im.metrics.fetched.WithLabelValues(lvSuccess).Inc()
			im.metrics.fetchDuration.Observe(time.Since(now).Seconds())
		}
	}()

	// Upload debug information of the discovered object files.
	im.ensureDebuginfoUploaded(ctx, mappings)

	var interp *runtime.Interpreter
	if im.shouldFetchInterpreterInfo {
		// Fetch interpreter information.
		// At this point we cannot tell if a process is a Python or Ruby interpreter so,
		// we will pay the cost for the excluded one if only one of them enabled.
		var err error
		interp, err = interpreter.Fetch(proc)
		if err != nil {
			level.Debug(im.logger).Log("msg", "failed to fetch interpreter information", "err", err, "pid", pid)
		}
		if interp != nil {
			level.Debug(im.logger).Log("msg", "interpreter information fetched", "interpreter", interp.Type, "version", interp.Version, "pid", pid)
		}
	}

	// No matter what happens with the debug information, we should continue.
	// And cache other process information.
	info = Info{
		im:          im,
		pid:         pid,
		Mappings:    mappings,
		Interpreter: interp,
	}
	im.cache.Add(pid, info)

	// Cache the mappings hash for future needs.
	hash, err := mappings.Hash()
	if err != nil {
		return Info{}, fmt.Errorf("failed to hash mappings: %w", err)
	}
	im.cacheForMappings.Add(pid, hash)

	now = time.Now()
	defer func() {
		im.metrics.metadataDuration.Observe(time.Since(now).Seconds())
	}()
	// Warm up the label manager cache. Best effort.
	if lErr := im.labelManager.Fetch(ctx, pid); lErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to warm up label manager cache: %w", lErr))
	}
	return info, err
}

// Info returns the cached information for the given process.
func (im *InfoManager) Info(ctx context.Context, pid int) (Info, error) {
	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Info")
	defer span.End()

	im.metrics.get.Inc()

	info, ok := im.cache.Get(pid)
	if ok {
		return info, nil
	}

	return im.fetch(ctx, pid, false)
}

// ensureDebuginfoUploaded extracts the debug information of the given mappings and uploads them to the debuginfo manager.
// It is a best effort operation, so it will continue even if it fails to ensure debug information of a mapping uploaded.
func (im *InfoManager) ensureDebuginfoUploaded(ctx context.Context, mappings Mappings) {
	if im.debuginfoManager == nil {
		return
	}

	for _, m := range mappings {
		if !m.containsDebuginfoToUpload {
			// Nothing to do for mappings without debuginfo.
			continue
		}

		// Doing this here prevents us from launching a goroutine just to check
		// the cache, which most of the time will be a hit.
		if _, ok := im.shouldInitiateUploadCache.Get(m.BuildID); ok {
			// The debug information of this mapping is already uploaded.
			continue
		}

		if _, exists := im.uploadInflight.LoadOrStore(m.BuildID, struct{}{}); exists {
			// The debug information of this mapping is already being uploaded.
			continue
		}

		// Schedule the debug information upload.
		im.schedule(ctx, m)
	}
}

func (im *InfoManager) schedule(ctx context.Context, m *Mapping) {
	j := im.uploadJobPool.Get().(*uploadJob) //nolint:forcetypeassert
	j.populate(ctx, m)

	defer func() {
		if r := recover(); r != nil {
			// Probably the upload job queue is closed.
			// That means we are shutting down.
			level.Warn(im.logger).Log("msg", "failed to schedule mapping upload", "err", r)
		}
	}()

	select {
	case <-ctx.Done():
		// Just to keep things clean.
		j.reset()
		im.uploadJobPool.Put(j)
		return
	case im.uploadJobQueue <- j:
	}
}

type uploadJob struct {
	ctx     context.Context //nolint:containedctx
	mapping *Mapping
}

func (j *uploadJob) populate(ctx context.Context, mapping *Mapping) {
	j.ctx = ctx
	j.mapping = mapping
}

func (j *uploadJob) reset() {
	j.ctx = nil
	j.mapping = nil
}

func (im *InfoManager) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancelCause(ctx)
	defer cancel(fmt.Errorf("process  info manager: %w", ctx.Err()))

	// Start the upload workers.
	for i := 0; i < 16; i++ {
		go func() {
			for {
				select {
				case <-wctx.Done():
					return
				case j, open := <-im.uploadJobQueue:
					if !open {
						return
					}

					// nolint:contextcheck
					im.uploadMapping(j.ctx, j.mapping)
					im.uploadInflight.Delete(j.mapping.BuildID)

					j.reset()
					im.uploadJobPool.Put(j)
				}
			}
		}()
	}

	// Wait for the context to be done.
	<-ctx.Done()
	return nil
}

func (im *InfoManager) uploadMapping(ctx context.Context, m *Mapping) {
	if err := ctx.Err(); err != nil {
		return
	}

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded.mapping")
	span.SetAttributes(attribute.Int("pid", m.PID))
	defer span.End() // The span is initially started in the for loop.

	// All the caches and references are based on the source file's buildID.

	shouldInitiateUpload, err := im.debuginfoManager.ShouldInitiateUpload(ctx, m.BuildID)
	if err != nil {
		im.metrics.uploadErrors.WithLabelValues(lvShouldInitiateUpload).Inc()
		err = fmt.Errorf("failed to check whether build ID exists: %w", err)
		level.Debug(im.logger).Log("msg", "upload mapping", "err", err, "buildid", m.BuildID, "filepath", m.AbsolutePath())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}

	if !shouldInitiateUpload {
		im.shouldInitiateUploadCache.Add(m.BuildID, struct{}{})
		return // The debug information is already uploaded.
	}

	if err := im.debuginfoManager.UploadMapping(ctx, m); err != nil {
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			im.metrics.uploadErrors.WithLabelValues(lvAlreadyClosed).Inc()
			return
		}
		im.metrics.uploadErrors.WithLabelValues(lvUnknown).Inc()
		err = fmt.Errorf("failed to ensure debug information uploaded: %w", err)
		level.Error(im.logger).Log("msg", "upload mapping", "err", err, "buildid", m.BuildID, "filepath", m.AbsolutePath())
		span.RecordError(err)
		return
	}
}

func (im *InfoManager) Close() error {
	close(im.uploadJobQueue)
	return nil
}
