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
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type DebuginfoManager interface {
	ExtractOrFindDebugInfo(context.Context, string, *objectfile.ObjectFile) (*objectfile.ObjectFile, error)
	Upload(context.Context, *objectfile.ObjectFile) error
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
)

type metrics struct {
	loadAttempts prometheus.Counter
	load         *prometheus.CounterVec
	loadDuration prometheus.Histogram
	get          prometheus.Counter

	// Total number of debug information uploads or failed uploads.
	upload *prometheus.CounterVec
	// Total duration with retries.
	uploadDuration prometheus.Histogram

	extractOrFind         *prometheus.CounterVec
	extractOrFindDuration prometheus.Histogram

	metadataDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		loadAttempts: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_load_attempts_total",
			Help: "Total number of debug information load attempts.",
		}),
		load: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_load_total",
			Help: "Total number of debug information loads.",
		}, []string{"result"}),
		loadDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "parca_agent_process_info_load_duration_seconds",
			Help:    "Duration of debug information loads.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120, 360},
		}),
		get: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_get_total",
			Help: "Total number of debug information gets.",
		}),
		upload: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_upload_total",
			Help: "Total number of debug information uploads.",
		}, []string{"result"}),
		uploadDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "parca_agent_process_info_upload_duration_seconds",
			Help:    "Duration of debug information uploads.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120, 360},
		}),
		extractOrFind: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_extract_or_find_total",
			Help: "Total number of debug information extractions.",
		}, []string{"result"}),
		extractOrFindDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "parca_agent_process_info_extract_or_find_duration_seconds",
			Help:    "Duration of debug information extractions.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120, 360},
		}),
		metadataDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "parca_agent_process_info_metadata_fetch_duration_seconds",
			Help:    "Duration of metadata fetches.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120, 360},
		}),
	}
	m.load.WithLabelValues(lvSuccess)
	m.load.WithLabelValues(lvFail)
	m.upload.WithLabelValues(lvSuccess)
	m.upload.WithLabelValues(lvFail)
	m.extractOrFind.WithLabelValues(lvSuccess)
	m.extractOrFind.WithLabelValues(lvFail)
	return m
}

type InfoManager struct {
	logger  log.Logger
	tracer  trace.Tracer
	metrics *metrics

	cache burrow.Cache
	sfg   *singleflight.Group // for loader.

	debuginfoSrcCache burrow.Cache // for debuginfo files.

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
			burrow.WithExpireAfterAccess(10*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "process_info")),
		),
		debuginfoSrcCache: burrow.New(
			burrow.WithMaximumSize(2048),
			burrow.WithExpireAfterAccess(10*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_source")),
		),
		mapManager:       mm,
		debuginfoManager: dim,
		labelManager:     lm,
		sfg:              &singleflight.Group{},
	}
}

type Info struct {
	im  *InfoManager
	pid int

	// TODO(kakkoyun): Put all the necessary (following) fields in this struct.
	// - PerfMaps
	// - Unwind Information
	Mappings Mappings
}

func (i Info) Labels(ctx context.Context) (model.LabelSet, error) {
	ctx, span := i.im.tracer.Start(ctx, "Info.Labels")
	defer span.End()

	// NOTICE: Caching is not necessary here since the label set is already cached in the label manager.
	return i.im.labelManager.LabelSet(ctx, i.pid)
}

// Fetch collects the required information for a process and stores it for future needs.
func (im *InfoManager) Fetch(ctx context.Context, pid int) error {
	im.metrics.loadAttempts.Inc()

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Fetch")
	defer span.End()

	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	if val, exists := im.cache.GetIfPresent(pid); exists {
		info, ok := val.(Info)
		if !ok {
			return fmt.Errorf("unexpected type in cache: %T", val)
		}
		// Always try to upload debug information of the discovered object files, in case it is not uploaded before.
		// Debuginfo manager makes sure that the debug information is uploaded only once.
		if im.debuginfoManager != nil {
			if err := im.extractAndUploadDebuginfo(ctx, pid, info.Mappings); err != nil {
				level.Warn(im.logger).Log("msg", "failed to upload debug information", "err", err)
			}
		}
		return nil
	}

	now := time.Now()
	_, err, _ := im.sfg.Do(strconv.Itoa(pid), func() (interface{}, error) {
		// Any operation in this block will be executed only once for a given pid.
		// However, it needs to be fast as possible since it will block other goroutines.
		// And to avoid missing information for the short lived processes, the extraction and finding of debug information
		// should be done as soon as possible.
		defer func() {
			im.metrics.loadDuration.Observe(time.Since(now).Seconds())
		}()

		mappings, err := im.mapManager.MappingsForPID(pid)
		if err != nil {
			return nil, err
		}

		// Upload debug information of the discovered object files.
		if im.debuginfoManager != nil {
			if err := im.extractAndUploadDebuginfo(ctx, pid, mappings); err != nil {
				level.Warn(im.logger).Log("msg", "failed to upload debug information", "err", err)
			}
			// No matter what happens with the debug information, we should continue.
			// And cache other process information.
			im.cache.Put(pid, Info{
				im:       im,
				pid:      pid,
				Mappings: mappings,
			})
		}
		return nil, nil //nolint:nilnil
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

// extractAndUploadDebuginfo extracts the debug information of the given mappings and uploads them to the debuginfo manager.
// It is a best effort operation, so it will continue even if it fails to extract or upload debug information of a mapping.
// The returned errors are either from the extraction or scheduling the upload of the debug information, not from the upload itself.
func (im *InfoManager) extractAndUploadDebuginfo(ctx context.Context, pid int, mappings Mappings) error {
	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.extractAndUploadDebuginfo")
	// NOTICE: This span is not ended here since it will be ended in the goroutine after waiting for all the debug information uploads.

	var (
		di       = im.debuginfoManager
		wg       = &sync.WaitGroup{}
		multiErr *multierror.Error
	)
	for _, m := range mappings {
		// There is no need to extract and upload debug information of non-symbolizable mappings.
		if !m.isSymbolizable() {
			continue
		}

		ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.extractAndUploadDebuginfo.mapping")
		span.SetAttributes(attribute.Int("pid", pid), attribute.String("buildid", m.objFile.BuildID), attribute.String("path", m.objFile.Path))

		var (
			srcObjFile = m.objFile // objectfile should exist and be open at this point.
			logger     = log.With(im.logger, "pid", pid, "buildid", srcObjFile.BuildID, "path", srcObjFile.Path)

			now        = time.Now()
			dbgObjFile *objectfile.ObjectFile
			err        error
		)

		// If the debuginfo file is already extracted or found, we do not need to do it again.
		// We just need to make sure it is uploaded.
		val, ok := im.debuginfoSrcCache.GetIfPresent(srcObjFile.BuildID)
		if ok {
			cachedObjFile, ok := val.(objectfile.ObjectFile)
			if !ok {
				span.End()
				return fmt.Errorf("unexpected type in cache: %T", val)
			}
			dbgObjFile = &cachedObjFile
		} else {
			// We upload the debug information files asynchronous and concurrently with retry.
			// However, first we need to find the debuginfo file or extract debuginfo from the executable.
			// For the short-lived processes, we may not complete the operation before the process exits.
			// Therefore, to be able shorten this window as much as possible, we extract and find the debuginfo
			// files synchronously and upload them asynchronously.
			// We still might be too slow to obtain the necessary file descriptors for certain short-lived processes.
			dbgObjFile, err = di.ExtractOrFindDebugInfo(ctx, m.Root(), srcObjFile)
			if err != nil {
				im.metrics.extractOrFind.WithLabelValues(lvFail).Inc()
				level.Error(logger).Log("msg", "failed to find or extract debuginfo is uploaded", "err", err)
				multiErr = multierror.Append(multiErr, err)
				span.End()
				continue
			}
			im.debuginfoSrcCache.Put(srcObjFile.BuildID, *dbgObjFile)
			im.metrics.extractOrFind.WithLabelValues(lvSuccess).Inc()
			im.metrics.extractOrFindDuration.Observe(time.Since(now).Seconds())
		}

		// Upload the debug information file.
		wg.Add(1)
		go func(span trace.Span) {
			defer wg.Done()
			defer span.End() // The span is initially started in the for loop.

			now := time.Now()
			defer func() {
				im.metrics.uploadDuration.Observe(time.Since(now).Seconds())
			}()

			logger := log.With(im.logger, "buildid", srcObjFile.BuildID, "path", srcObjFile.Path)

			// NOTICE: The upload timeout and upload retry logic controlled by debuginfo manager.
			if err := di.Upload(ctx, dbgObjFile); err != nil {
				im.metrics.upload.WithLabelValues(lvFail).Inc()
				span.RecordError(err)
				level.Error(logger).Log("msg", "failed to upload debuginfo", "err", err)
				return
			}
			im.metrics.upload.WithLabelValues(lvSuccess).Inc()
			// TODO(kakkoyun): We might need a more sophisticated closing logic if the first normalization operation is not happened yet.
			if err := srcObjFile.Close(); err != nil {
				level.Debug(logger).Log("msg", "failed to close objfile", "err", err)
			}
		}(span)
	}
	go func() {
		defer span.End() // The span is initially started in the beginning of the function.

		wg.Wait()
	}()
	return multiErr.ErrorOrNil()
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
		panic("received the wrong type in the info cache")
	}
	return &info, nil
}
