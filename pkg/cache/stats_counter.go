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

type BurrowStatsCounter struct {
	logger log.Logger

	hits          prometheus.Counter
	miss          prometheus.Counter
	loadSuccess   prometheus.Counter
	loadError     prometheus.Counter
	totalLoadTime prometheus.Histogram
	eviction      prometheus.Counter
}

func NewBurrowStatsCounter(logger log.Logger, reg prometheus.Registerer, name string) *BurrowStatsCounter {
	reg = prometheus.WrapRegistererWith(prometheus.Labels{"cache": name}, reg)
	return &BurrowStatsCounter{
		hits: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits.",
		}),
		miss: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_miss_total",
			Help: "Total number of cache misses.",
		}),
		loadSuccess: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_load_success_total",
			Help: "Total number of successful cache loads.",
		}),
		loadError: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_load_error_total",
			Help: "Total number of cache load errors.",
		}),
		totalLoadTime: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:    "cache_load_duration_seconds",
			Help:    "Total time spent loading cache.",
			Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1},
		}),
		eviction: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_evictions_total",
			Help: "Total number of cache evictions.",
		}),
	}
}

func (c *BurrowStatsCounter) RecordHits(hits uint64) {
	c.hits.Add(float64(hits))
}

func (c *BurrowStatsCounter) RecordMisses(miss uint64) {
	c.miss.Add(float64(miss))
}

func (c *BurrowStatsCounter) RecordLoadSuccess(loadTime time.Duration) {
	c.loadSuccess.Inc()
	c.totalLoadTime.Observe(loadTime.Seconds())
}

func (c *BurrowStatsCounter) RecordLoadError(loadTime time.Duration) {
	c.loadError.Inc()
	c.totalLoadTime.Observe(loadTime.Seconds())
}

func (c *BurrowStatsCounter) RecordEviction() {
	c.eviction.Inc()
}

func (c *BurrowStatsCounter) Snapshot(s *burrow.Stats) {
	var err error
	s.HitCount, err = collectCounter(c.hits)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache hits", "err", err)
	}
	s.MissCount, err = collectCounter(c.miss)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache misses", "err", err)
	}
	s.LoadSuccessCount, err = collectCounter(c.loadSuccess)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache load success", "err", err)
	}
	s.LoadErrorCount, err = collectCounter(c.loadError)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache load error", "err", err)
	}
	totalTime, err := collectHistogramSum(c.totalLoadTime)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache load time", "err", err)
	}
	s.TotalLoadTime = time.Duration(totalTime)
	s.EvictionCount, err = collectCounter(c.eviction)
	if err != nil {
		level.Warn(c.logger).Log("msg", "failed to collect cache evictions", "err", err)
	}
}

func collect(col prometheus.Collector) (*dto.Metric, error) {
	// This could be done with prometheus.CounterFunc and atomic.Counter easier,
	// but it would make it harder to use the same code for histograms.

	// Snapshot function is called manually and we don't plan to use it.
	// For completeness, we implement it.
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

func collectCounter(col prometheus.Collector) (uint64, error) {
	pb, err := collect(col)
	if err != nil {
		return 0, err
	}

	return uint64(pb.GetCounter().GetValue()), nil
}

func collectHistogramSum(col prometheus.Collector) (uint64, error) {
	pb, err := collect(col)
	if err != nil {
		return 0, err
	}
	return uint64(pb.GetHistogram().GetSampleSum()), nil
}
