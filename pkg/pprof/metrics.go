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

package pprof

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	labelFrameDropReasonMappingNil          = "mapping_nil"
	labelStackDropReasonNormalizationFailed = "normalization_failed"
)

type converterMetrics struct {
	frameDrop *prometheus.CounterVec
	stackDrop *prometheus.CounterVec
}

func newConverterMetrics(reg prometheus.Registerer) *converterMetrics {
	m := &converterMetrics{
		frameDrop: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_frame_drop_total",
				Help:        "Number of addresses dropped from the profile.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"reason"},
		),
		stackDrop: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_converter_stack_drop_total",
				Help:        "Total number of stacks dropped from the profile during conversion.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"reason"},
		),
	}

	m.frameDrop.WithLabelValues(labelFrameDropReasonMappingNil)

	return m
}
