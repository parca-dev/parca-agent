// Copyright 2026 The Parca Authors
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

package gpumetrics

import (
	"slices"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

// MetricBuffer accumulates data points by metric name for one resource until
// the next export.
type MetricBuffer struct {
	metrics map[string]pmetric.Metric
}

func newMetricBuffer() *MetricBuffer {
	return &MetricBuffer{metrics: map[string]pmetric.Metric{}}
}

// Points returns name's data points, creating the metric from its spec on
// first use. name must be one of the Metric* constants.
func (b *MetricBuffer) Points(name string) pmetric.NumberDataPointSlice {
	m, ok := b.metrics[name]
	if !ok {
		spec, ok := metricSpecs[name]
		if !ok {
			panic("gpumetrics: no metricSpec for " + name)
		}
		m = pmetric.NewMetric()
		m.SetName(name)
		m.SetUnit(spec.unit)
		m.SetDescription(spec.description)
		if spec.sum {
			s := m.SetEmptySum()
			s.SetIsMonotonic(false)
			s.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		} else {
			m.SetEmptyGauge()
		}
		b.metrics[name] = m
	}
	if m.Type() == pmetric.MetricTypeSum {
		return m.Sum().DataPoints()
	}
	return m.Gauge().DataPoints()
}

// moveTo moves every metric into ms, in name order so output is stable.
func (b *MetricBuffer) moveTo(ms pmetric.MetricSlice) {
	names := make([]string, 0, len(b.metrics))
	for name := range b.metrics {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		b.metrics[name].MoveTo(ms.AppendEmpty())
	}
	clear(b.metrics)
}
