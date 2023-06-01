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
	EnsureUploaded(context.Context, string, *objectfile.ObjectFile) (bool, error)
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
)

type metrics struct {
	fetchAttempts    prometheus.Counter
	fetched          *prometheus.CounterVec
	fetchDuration    prometheus.Histogram
	get              prometheus.Counter
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
			Name:    "parca_agent_process_info_fetch_duration_seconds",
			Help:    "Duration of debug information loads.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120, 360},
		}),
		get: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_get_total",
			Help: "Total number of debug information gets.",
		}),
		metadataDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "parca_agent_process_info_metadata_fetch_duration_seconds",
			Help:    "Duration of metadata fetches.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120, 360},
		}),
	}
	m.fetched.WithLabelValues(lvSuccess)
	m.fetched.WithLabelValues(lvFail)
	m.fetched.WithLabelValues(lvShared)
	return m
}

type InfoManager struct {
	logger  log.Logger
	tracer  trace.Tracer
	metrics *metrics

	cache burrow.Cache
	sfg   *singleflight.Group // for loader.

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
		sfg:              &singleflight.Group{},
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
func (im *InfoManager) Fetch(ctx context.Context, pid int) error {
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
		if err := im.ensureDebuginfoUploaded(ctx, pid, info.Mappings); err != nil {
			level.Debug(im.logger).Log("msg", "failed to upload debug information", "err", err)
		}
		return nil
	}

	now := time.Now()
	_, err, shared := im.sfg.Do(strconv.Itoa(pid), func() (interface{}, error) {
		// Any operation in this block will be executed only once for a given pid.
		// However, it needs to be fast as possible since it will block other goroutines.
		// And to avoid missing information for the short lived processes, the extraction and finding of debug information
		// should be done as soon as possible.

		mappings, err := im.mapManager.MappingsForPID(pid)
		if err != nil {
			return nil, err
		}

		// Upload debug information of the discovered object files.
		if err := im.ensureDebuginfoUploaded(ctx, pid, mappings); err != nil {
			level.Debug(im.logger).Log("msg", "failed to (initial) upload debug information", "err", err)
		}

		// No matter what happens with the debug information, we should continue.
		// And cache other process information.
		im.cache.Put(pid, Info{
			im:       im,
			pid:      pid,
			Mappings: mappings,
		})
		return nil, nil //nolint:nilnil
	})
	if err != nil {
		im.metrics.fetched.WithLabelValues(lvFail).Inc()
		if !errors.Is(err, ErrProcNotFound) {
			im.sfg.Forget(strconv.Itoa(pid))
		}
	} else {
		if shared {
			im.metrics.fetched.WithLabelValues(lvShared).Inc()
		} else {
			im.metrics.fetched.WithLabelValues(lvSuccess).Inc()
			im.metrics.fetchDuration.Observe(time.Since(now).Seconds())
		}
	}

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
// The returned errors are either from the scheduling the upload of the debug information, not from the upload itself.
func (im *InfoManager) ensureDebuginfoUploaded(ctx context.Context, pid int, mappings Mappings) error {
	if im.debuginfoManager == nil {
		return nil
	}

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded")
	// NOTICE: This span is not ended here with a defer,
	// - because it will be ended in the goroutine after waiting for all the debug information uploads.

	var (
		di = im.debuginfoManager
		wg = &sync.WaitGroup{}

		schedulingErrors error
	)
	for _, m := range mappings {
		// There is no need to extract and upload debug information of non-symbolizable mappings.
		if !m.isSymbolizable() {
			continue
		}

		if m.uploaded {
			continue
		}

		ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded.mapping")

		// ObjectFile should be cached in the pool by this point.
		src, err := im.mapManager.objFilePool.Open(m.fullPath())
		if err != nil {
			span.RecordError(err)
			schedulingErrors = errors.Join(schedulingErrors, err)
			continue
		}
		defer src.HoldOn()

		span.SetAttributes(
			attribute.Int("pid", pid),
			attribute.String("buildid", src.BuildID),
			attribute.String("path", src.Path),
		)

		wg.Add(1)
		go func(span trace.Span, m *Mapping, src *objectfile.ObjectFile) {
			defer wg.Done()
			defer src.HoldOn()

			// Upload the debug information file.
			uploaded, err := di.EnsureUploaded(ctx, m.Root(), src)
			if err != nil {
				err = fmt.Errorf("failed to ensure debug information uploaded: %w", err)
				span.RecordError(err)

				schedulingErrors = errors.Join(schedulingErrors, err)
				return
			}
			if uploaded {
				m.uploaded = true
			}
			span.End() // The span is initially started in the for loop.
		}(span, m, src)
	}
	go func() {
		defer span.End() // The span is initially started in the beginning of the function.

		wg.Wait()
	}()
	return schedulingErrors
}
