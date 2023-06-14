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
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/parca-dev/parca-agent/pkg/cache"
)

type DebuginfoManager interface {
	ShouldInitiateUpload(context.Context, string) (bool, error)
	UploadMapping(context.Context, *Mapping) error
	Close() error
}

// TODO: Unify PID types.
type LabelManager interface {
	Fetch(ctx context.Context, pid int) error
	LabelSet(ctx context.Context, pid int) (model.LabelSet, error)
}

type Cache[K comparable, V any] interface {
	Add(K, V)
	Get(K) (V, bool)
	Peek(K) (V, bool)
	Remove(K)
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
	shouldInitiateUploadCache Cache[string, struct{}]
	uploadInflight            *sync.Map

	mapManager       *MapManager
	debuginfoManager DebuginfoManager
	labelManager     LabelManager
}

func NewInfoManager(
	logger log.Logger,
	tracer trace.Tracer,
	reg prometheus.Registerer,
	mm *MapManager,
	dim DebuginfoManager,
	lm LabelManager,
	profilingDuration time.Duration,
	cacheTTL time.Duration,
) *InfoManager {
	return &InfoManager{
		logger:  logger,
		tracer:  tracer,
		metrics: newMetrics(reg),
		cache: cache.NewLRUCacheWithTTL[int, Info](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "process_info"}, reg),
			2048,
			12*profilingDuration,
		),
		shouldInitiateUploadCache: cache.NewLRUCacheWithTTL[string, struct{}](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "debuginfo_should_initiate"}, reg),
			10000,
			cacheTTL,
		),
		uploadInflight:   &sync.Map{},
		mapManager:       mm,
		debuginfoManager: dim,
		labelManager:     lm,
	}
}

type Info struct {
	im  *InfoManager
	pid int

	// TODO(kakkoyun): Put all the necessary (following) references in this struct.
	// - PerfMaps, JITDUMP, etc.
	//   * "/proc/%d/root/tmp/perf-%d.map" or "/proc/%d/root/tmp/perf-%d.dump" for PerfMaps
	//   * "/proc/%d/root/jit-%d.dump" for JITDUMP
	// - Unwind Information
	Mappings Mappings
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

	return im.fetch(ctx, pid)
}

// Fetch collects the required information for a process and stores it for future needs.
func (im *InfoManager) fetch(ctx context.Context, pid int) (info Info, err error) { //nolint:nonamedreturns
	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	info, exists := im.cache.Peek(pid)
	if exists {
		im.ensureDebuginfoUploaded(ctx, pid, info.Mappings)
		return info, nil
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

	// Any operation in this block will be executed only once for a given pid.
	// However, it needs to be fast as possible since it will block other goroutines.
	// And to avoid missing information for the short lived processes, the extraction and finding of debug information
	// should be done as soon as possible.

	mappings, err := im.mapManager.MappingsForPID(pid)
	if err != nil {
		return Info{}, err
	}

	// Upload debug information of the discovered object files.
	im.ensureDebuginfoUploaded(ctx, pid, mappings)

	// No matter what happens with the debug information, we should continue.
	// And cache other process information.
	info = Info{
		im:       im,
		pid:      pid,
		Mappings: mappings,
	}
	im.cache.Add(pid, info)

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

	return im.fetch(ctx, pid)
}

// ensureDebuginfoUploaded extracts the debug information of the given mappings and uploads them to the debuginfo manager.
// It is a best effort operation, so it will continue even if it fails to ensure debug information of a mapping uploaded.
func (im *InfoManager) ensureDebuginfoUploaded(ctx context.Context, pid int, mappings Mappings) {
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

		go func(m *Mapping) {
			defer im.uploadInflight.Delete(m.BuildID)

			if err := ctx.Err(); err != nil {
				return
			}

			ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded.mapping")
			span.SetAttributes(attribute.Int("pid", pid))
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
		}(m)
	}
}
