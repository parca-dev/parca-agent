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

package cpu

import (
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metrics struct {
	obtainAttempts    *prometheus.CounterVec
	obtainMapAttempts *prometheus.CounterVec
	obtainDuration    prometheus.Histogram
	symbolizeDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *metrics {
	return &metrics{
		obtainAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_attempts_total",
				Help:        "Total number of attempts to obtain a profile.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"status"},
		),
		obtainMapAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_map_attempts_total",
				Help:        "Number of attempts to unwind stacks in kernel and user space.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"stack", "action", "status"},
		),
		obtainDuration: promauto.With(reg).NewHistogram(
			prometheus.HistogramOpts{
				Name:                        "parca_agent_profiler_attempt_duration_seconds",
				Help:                        "The duration it takes to collect profiles from the BPF maps",
				ConstLabels:                 map[string]string{"type": "cpu"},
				NativeHistogramBucketFactor: 1.1,
			},
		),
		symbolizeDuration: promauto.With(reg).NewHistogram(
			prometheus.HistogramOpts{
				Name:                        "parca_agent_profiler_symbolize_duration_seconds",
				Help:                        "The duration it takes to symbolize and convert to pprof",
				ConstLabels:                 map[string]string{"type": "cpu"},
				NativeHistogramBucketFactor: 1.1,
			},
		),
	}
}

type bpfMetrics struct {
	mapName         string
	bpfMapKeySize   float64
	bpfMapValueSize float64
	bpfMaxEntry     float64
	bpfMemlock      float64
}

type bpfMetricsCollector struct {
	logger log.Logger
	m      *bpf.Module
	pid    int
}

func newBPFMetricsCollector(p *CPU, m *bpf.Module, pid int) *bpfMetricsCollector {
	return &bpfMetricsCollector{
		logger: p.logger,
		m:      m,
		pid:    pid,
	}
}

var (
	descBPFMemlock = prometheus.NewDesc(
		"parca_agent_bpf_map_memlock",
		"Memlock value held by BPF map",
		[]string{"bpf_map_name"}, nil,
	)
	descBPFMapKeySize = prometheus.NewDesc(
		"parca_agent_bpf_map_key_size",
		"Key size for BPF map",
		[]string{"bpf_map_name"}, nil,
	)
	descBPFMapValueSize = prometheus.NewDesc(
		"parca_agent_bpf_map_value_size",
		"Value size BPF map",
		[]string{"bpf_map_name"}, nil,
	)
	descBPFMapMaxEntries = prometheus.NewDesc(
		"parca_agent_bpf_map_max_entries",
		"Maximum entries in BPF map",
		[]string{"bpf_map_name"}, nil,
	)
)

func (c *bpfMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descBPFMemlock
	ch <- descBPFMapKeySize
	ch <- descBPFMapValueSize
	ch <- descBPFMapMaxEntries
}

func (c *bpfMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	for _, bpfMetrics := range c.getBPFMetrics() {
		ch <- prometheus.MustNewConstMetric(descBPFMemlock, prometheus.GaugeValue, bpfMetrics.bpfMemlock, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapKeySize, prometheus.GaugeValue, bpfMetrics.bpfMapKeySize, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapValueSize, prometheus.GaugeValue, bpfMetrics.bpfMapValueSize, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapMaxEntries, prometheus.GaugeValue, bpfMetrics.bpfMaxEntry, bpfMetrics.mapName)
	}
}
