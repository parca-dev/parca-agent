// Copyright (c) 2022 The Parca Authors
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
	missingStacks                *prometheus.CounterVec
	failedStackReads             *prometheus.CounterVec
	failedStackUnwindingAttempts *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	return &metrics{
		missingStacks: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_missing_stacks_total",
				Help: "Number of missing profile stacks",
			},
			[]string{"type"},
		),
		failedStackUnwindingAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_failed_stack_unwinding_attempts_total",
				Help: "Number of failed stack unwinding attempts",
			},
			[]string{"type"},
		),
		failedStackReads: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_failed_stack_read_total",
				Help: "Number of failed stack reads",
			},
			[]string{"type"},
		),
	}
}
