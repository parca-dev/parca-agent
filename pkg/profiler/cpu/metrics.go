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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	labelUser         = "user"
	labelKernel       = "kernel"
	labelKernelUnwind = "kernel_unwind"
	labelDwarfUnwind  = "dwarf_unwind"
	labelError        = "error"
	labelMissing      = "missing"
	labelFailed       = "failed"
	labelSuccess      = "success"

	labelStackDropReasonKey              = "read_stack_key"
	labelStackDropReasonUserDWARF        = "read_user_stack_with_dwarf"
	labelStackDropReasonUserFramePointer = "read_user_stack_with_frame_pointer"
	labelStackDropReasonKernel           = "read_kernel_stack"
	labelStackDropReasonCount            = "read_stack_count"
	labelStackDropReasonZeroCount        = "read_stack_count_zero"
	labelStackDropReasonIterator         = "iterator"
	labelStackDropReasonProcessInfo      = "process_info"

	labelFrameDropReasonProcessInfo   = "process_info"
	labelFrameDropReasonMappingNil    = "mapping_nil"
	labelFrameDropReasonNormalization = "normalization"
)

type metrics struct {
	// profile level
	obtainAttempts *prometheus.CounterVec
	obtainDuration prometheus.Histogram

	// stack level
	stackDrop       *prometheus.CounterVec
	readMapAttempts *prometheus.CounterVec

	// frame level
	frameDrop *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		obtainAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_attempts_total",
				Help:        "Total number of attempts to obtain a profile.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"status"},
		),
		obtainDuration: promauto.With(reg).NewHistogram(
			prometheus.HistogramOpts{
				Name:                        "parca_agent_profiler_attempt_duration_seconds",
				Help:                        "The duration it takes to collect profiles from the BPF maps",
				ConstLabels:                 map[string]string{"type": "cpu"},
				NativeHistogramBucketFactor: 1.1,
			},
		),
		stackDrop: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_stack_drop_total",
				Help:        "Total number of stacks dropped from the profile.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"reason"},
		),
		readMapAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_map_read_attempts_total",
				Help:        "Number of attempts to read from the BPF maps.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"stack", "action", "status"},
		),
		frameDrop: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_frame_drop_total",
				Help:        "Number of addresses dropped from the profile.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"reason"},
		),
	}
	m.obtainAttempts.WithLabelValues(labelSuccess)
	m.obtainAttempts.WithLabelValues(labelError)

	m.stackDrop.WithLabelValues(labelStackDropReasonKey)
	m.stackDrop.WithLabelValues(labelStackDropReasonUserDWARF)
	m.stackDrop.WithLabelValues(labelStackDropReasonUserFramePointer)
	m.stackDrop.WithLabelValues(labelStackDropReasonKernel)
	m.stackDrop.WithLabelValues(labelStackDropReasonCount)
	m.stackDrop.WithLabelValues(labelStackDropReasonZeroCount)
	m.stackDrop.WithLabelValues(labelStackDropReasonIterator)
	m.stackDrop.WithLabelValues(labelStackDropReasonProcessInfo)

	m.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelSuccess)
	m.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelError)
	m.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelMissing)
	m.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelFailed)

	m.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelSuccess)
	m.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelError)
	m.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelMissing)
	m.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelFailed)

	m.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelSuccess)
	m.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelError)
	m.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelMissing)
	m.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelFailed)

	m.frameDrop.WithLabelValues(labelFrameDropReasonProcessInfo)
	m.frameDrop.WithLabelValues(labelFrameDropReasonMappingNil)
	m.frameDrop.WithLabelValues(labelFrameDropReasonNormalization)

	return m
}
