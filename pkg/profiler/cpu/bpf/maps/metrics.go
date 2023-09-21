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

package bpfmaps

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	labelHash           = "hash"
	labelUnwindTableAdd = "unwind_table_add"
)

type metrics struct {
	refreshProcessInfoErrors *prometheus.CounterVec

	// Map clean.
	mapCleanErrors *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		refreshProcessInfoErrors: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name:        "parca_agent_profiler_bpf_maps_refresh_proc_info_errors_total",
			Help:        "Number of errors refreshing process info",
			ConstLabels: map[string]string{"type": "cpu"},
		}, []string{"error"}),
		mapCleanErrors: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name:        "parca_agent_profiler_bpf_maps_clean_errors_total",
			Help:        "Number of errors cleaning BPF maps",
			ConstLabels: map[string]string{"type": "cpu"},
		}, []string{"map"}),
	}

	m.refreshProcessInfoErrors.WithLabelValues(labelHash)
	m.refreshProcessInfoErrors.WithLabelValues(labelUnwindTableAdd)

	m.mapCleanErrors.WithLabelValues(StackTracesMapName)
	m.mapCleanErrors.WithLabelValues(DWARFStackTracesMapName)
	m.mapCleanErrors.WithLabelValues(StackCountsMapName)
	m.mapCleanErrors.WithLabelValues(ProcessInfoMapName)
	m.mapCleanErrors.WithLabelValues(UnwindInfoChunksMapName)
	return m
}
