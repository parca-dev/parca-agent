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
	burrow "github.com/goburrow/cache"
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

	cache            burrow.Cache
	fetchInProgress  *sync.Map
	uploadInprogress *sync.Map

	mapManager       *MapManager
	debuginfoManager DebuginfoManager
	labelManager     LabelManager
}

func NewInfoManager(logger log.Logger, tracer trace.Tracer, reg prometheus.Registerer, mm *MapManager, dim DebuginfoManager, lm LabelManager, profilingDuration time.Duration) *InfoManager {
	return &InfoManager{
		logger:  logger,
		tracer:  tracer,
		metrics: newMetrics(reg),
		cache: burrow.New(
			burrow.WithMaximumSize(2048),
			burrow.WithExpireAfterAccess(12*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "process_info")),
		),
		mapManager:       mm,
		debuginfoManager: dim,
		labelManager:     lm,
		fetchInProgress:  &sync.Map{},
		uploadInprogress: &sync.Map{},
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

// Fetch collects the required information for a process and stores it for future needs.
func (im *InfoManager) Fetch(ctx context.Context, pid int) (err error) { //nolint:nonamedreturns
	im.metrics.fetchAttempts.Inc()

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Fetch")
	defer span.End()

	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	if val, exists := im.cache.GetIfPresent(pid); exists {
		info, ok := val.(Info)
		if !ok {
			return fmt.Errorf("unexpected type in cache: %T", val)
		}

		im.metrics.fetched.WithLabelValues(lvShared).Inc()

		// Always try to upload debug information of the discovered object files, in case it is not uploaded before.
		// Debuginfo manager makes sure that the debug information is uploaded only once.
		im.ensureDebuginfoUploaded(ctx, pid, info.Mappings)
		return nil
	}

	if _, exists := im.fetchInProgress.LoadOrStore(pid, struct{}{}); exists {
		return nil
	}
	defer im.fetchInProgress.Delete(pid)

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
		return err
	}

	// Upload debug information of the discovered object files.
	im.ensureDebuginfoUploaded(ctx, pid, mappings)

	// No matter what happens with the debug information, we should continue.
	// And cache other process information.
	im.cache.Put(pid, Info{
		im:       im,
		pid:      pid,
		Mappings: mappings,
	})

	now = time.Now()
	defer func() {
		im.metrics.metadataDuration.Observe(time.Since(now).Seconds())
	}()
	// Warm up the label manager cache. Best effort.
	if lErr := im.labelManager.Fetch(ctx, pid); lErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to warm up label manager cache: %w", lErr))
	}
	return err
}

// Info returns the cached information for the given process.
func (im *InfoManager) Info(ctx context.Context, pid int) (*Info, error) {
	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Info")
	defer span.End()

	im.metrics.get.Inc()

	v, ok := im.cache.GetIfPresent(pid)
	if !ok {
		if err := im.Fetch(ctx, pid); err != nil {
			return nil, err
		}
		// Fetch should have populated the cache.
		v, ok = im.cache.GetIfPresent(pid)
		if !ok {
			return nil, fmt.Errorf("failed to load debug information for pid %d", pid)
		}
	}

	info, ok := v.(Info)
	if !ok {
		return nil, fmt.Errorf("unexpected type in cache: %T", v)
	}
	return &info, nil
}

// ensureDebuginfoUploaded extracts the debug information of the given mappings and uploads them to the debuginfo manager.
// It is a best effort operation, so it will continue even if it fails to ensure debug information of a mapping uploaded.
func (im *InfoManager) ensureDebuginfoUploaded(ctx context.Context, pid int, mappings Mappings) {
	if im.debuginfoManager == nil {
		return
	}

	if _, exists := im.uploadInprogress.LoadOrStore(pid, struct{}{}); exists {
		return
	}
	defer im.uploadInprogress.Delete(pid)

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded")
	defer span.End() // The span is initially started in the beginning of the function.

	span.SetAttributes(attribute.Int("pid", pid))

	var (
		di = im.debuginfoManager
		wg = &sync.WaitGroup{}
	)
	for _, m := range mappings {
		if !m.containsDebuginfoToUpload {
			// Nothing to do for mappings without debuginfo.
			continue
		}

		ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded.mapping")
		wg.Add(1)
		go func(span trace.Span, m *Mapping) {
			defer span.End() // The span is initially started in the for loop.
			defer wg.Done()

			// All the caches and references are based on the source file's buildID.

			shouldInitiateUpload, err := di.ShouldInitiateUpload(ctx, m.BuildID)
			if err != nil {
				im.metrics.uploadErrors.WithLabelValues(lvShouldInitiateUpload).Inc()
				err = fmt.Errorf("failed to check whether build ID exists: %w", err)
				level.Debug(im.logger).Log("msg", "upload mapping", "err", err, "buildid", m.BuildID, "filepath", m.AbsolutePath())
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return
			}

			if !shouldInitiateUpload {
				return // The debug information is already uploaded.
			}

			if err := di.UploadMapping(ctx, m); err != nil {
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
		}(span, m)
	}

	wg.Wait()
}
