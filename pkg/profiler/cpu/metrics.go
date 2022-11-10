// Copyright 2022 The Parca Authors
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
