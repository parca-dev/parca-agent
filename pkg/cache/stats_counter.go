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

package cache

import (
	"fmt"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"

	burrow "github.com/goburrow/cache"
)

const (
	lvMiss = "miss"
	lvHit  = "hit"

	lvSuccess = "success"
	lvError   = "error"
)

// StatsCounter is an interface for recording cache stats for goburrow.Cache.
// The StatsCounter can be found at
// - https://github.com/goburrow/cache/blob/f6da914dd6e3546dffa8802919dbca80cd33abe3/stats.go#L67
var _ burrow.StatsCounter = (*burrowStatsCounter)(nil)

// burrowStatsCounter is a StatsCounter implementation for burrow cache.
// It is a wrapper around prometheus metrics.
// It has been intended to passed through the cache using cache.WithStatsCounter option
// - https://github.com/goburrow/cache/blob/f6da914dd6e3546dffa8802919dbca80cd33abe3/local.go#L552
type burrowStatsCounter struct {
	logger log.Logger
	reg    prometheus.Registerer

	requests *prometheus.CounterVec
	eviction prometheus.Counter

	trackLoadingCacheStats bool
	load                   *prometheus.CounterVec
	loadTotalTime          prometheus.Histogram
}

// Option add options for default Cache.
type Option func(c *burrowStatsCounter)

// WithTrackLoadingCacheStats enables tracking of loading cache stats.
// It is disabled by default.
func WithTrackLoadingCacheStats() Option {
	return func(c *burrowStatsCounter) {
		c.trackLoadingCacheStats = true
		c.load = promauto.With(c.reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cache_load_total",
			Help: "Total number of successful cache loads.",
		}, []string{"result"})
		c.loadTotalTime = promauto.With(c.reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "cache_load_duration_seconds",
			Help:    "Total time spent loading cache.",
			Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1},
		})
	}
}

// NewBurrowStatsCounter creates a new StatsCounter.
//
// RecordLoadSuccess and RecordLoadError methods are called by Get methods on a successful and failed load respectively.
// Get method only called by LoadingCache implementation.
func NewBurrowStatsCounter(logger log.Logger, reg prometheus.Registerer, name string, options ...Option) *burrowStatsCounter {
	reg = prometheus.WrapRegistererWith(prometheus.Labels{"cache": name}, reg)
	s := &burrowStatsCounter{
		logger: logger,
		reg:    reg,

		requests: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "cache_requests_total",
			Help: "Total number of cache requests.",
		}, []string{"result"}),
		eviction: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_evictions_total",
			Help: "Total number of cache evictions.",
		}),
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

// RecordHits records the number of hits.
// It is part of the burrow.StatsCounter interface.
//
// This method is called by Get and GetIfPresent methods on a cache hit.
func (c *burrowStatsCounter) RecordHits(hits uint64) {
	c.requests.WithLabelValues(lvHit).Add(float64(hits))
}

// RecordMisses records the number of misses.
// It is part of the burrow.StatsCounter interface.
//
// This method is called by Get and GetIfPresent methods method on a cache miss.
func (c *burrowStatsCounter) RecordMisses(misses uint64) {
	c.requests.WithLabelValues(lvMiss).Add(float64(misses))
}

// RecordLoadSuccess records the number of successful loads.
// It is part of the burrow.StatsCounter interface.
//
// This method is called by Get methods on a successful load.
func (c *burrowStatsCounter) RecordLoadSuccess(loadTime time.Duration) {
	if !c.trackLoadingCacheStats {
		return
	}
	c.load.WithLabelValues(lvSuccess).Inc()
	c.loadTotalTime.Observe(loadTime.Seconds())
}

// RecordLoadError records the number of failed loads.
// It is part of the burrow.StatsCounter interface.
//
// This method is called by Get methods on a failed load.
func (c *burrowStatsCounter) RecordLoadError(loadTime time.Duration) {
	if !c.trackLoadingCacheStats {
		return
	}
	c.load.WithLabelValues(lvError).Inc()
	c.loadTotalTime.Observe(loadTime.Seconds())
}

// RecordEviction records the number of evictions.
// It is part of the burrow.StatsCounter interface.
func (c *burrowStatsCounter) RecordEviction() {
	c.eviction.Inc()
}

// Snapshot records the current stats.
// It is part of the burrow.StatsCounter interface.
//
// This method is called only by Stats method. And it is just for debugging purpose.
// Snapshot function is called manually and we don't plan to use it.
// For completeness, we implemented it.
func (c *burrowStatsCounter) Snapshot(s *burrow.Stats) {
	var err error
	s.HitCount, err = currentCounterVecValue(c.requests, lvHit)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache hits", "err", err)
	}
	s.MissCount, err = currentCounterVecValue(c.requests, lvMiss)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache misses", "err", err)
	}
	s.EvictionCount, err = currentCounterValue(c.eviction)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache evictions", "err", err)
	}

	if !c.trackLoadingCacheStats {
		return
	}
	s.LoadSuccessCount, err = currentCounterVecValue(c.load, lvSuccess)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache load success", "err", err)
	}
	s.LoadErrorCount, err = currentCounterVecValue(c.load, lvError)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache load error", "err", err)
	}
	totalTime, err := currentHistogramSumValue(c.loadTotalTime)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache load time", "err", err)
	}
	s.TotalLoadTime = time.Duration(totalTime)
}

func currentMetric(col prometheus.Collector) (*dto.Metric, error) {
	// This could be done with prometheus.CounterFunc and atomic variables easier,
	// however it would make it harder to use the same code for histograms.
	// See:
	//
	//	var requestsCounter uint64 = 0
	//	prometheus.MustRegister(prometheus.NewCounterFunc(
	//		prometheus.CounterOpts{
	//			Name: "requests_total",
	//			Help: "Counts number of requests",
	//		},
	//		func() float64 {
	//			return float64(atomic.LoadUint64(&requestsCounter))
	//		}))
	//	atomic.AddUint64(&requestsCounter, 1)
	//
	// Moreover, prometheus metrics are optimized for writing, so it is better to stick with them.
	//
	// The prometheus/testutil package uses the same approach as here.
	// https://github.com/prometheus/client_golang/issues/486
	// e.g. https://github.com/prometheus/client_golang/blob/v1.14.0/prometheus/testutil/testutil.go
	var (
		m     prometheus.Metric
		count int
		ch    = make(chan prometheus.Metric)
		done  = make(chan struct{})
	)

	go func() {
		for m = range ch {
			count++
		}
		close(done)
	}()

	col.Collect(ch)
	close(ch)
	<-done

	if count != 1 {
		return nil, fmt.Errorf("collected %d metrics instead of exactly 1", count)
	}

	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		return nil, fmt.Errorf("error happened while collecting metrics: %w", err)
	}

	return pb, nil
}

func currentCounterVecValue(m *prometheus.CounterVec, lvs ...string) (uint64, error) {
	pb := &dto.Metric{}
	if err := m.WithLabelValues(lvs...).Write(pb); err != nil {
		return 0, err
	}
	return uint64(pb.GetCounter().GetValue()), nil
}

func currentCounterValue(col prometheus.Collector) (uint64, error) {
	pb, err := currentMetric(col)
	if err != nil {
		return 0, err
	}
	return uint64(pb.GetCounter().GetValue()), nil
}

func currentHistogramSumValue(col prometheus.Collector) (uint64, error) {
	pb, err := currentMetric(col)
	if err != nil {
		return 0, err
	}
	return uint64(pb.GetHistogram().GetSampleSum()), nil
}
