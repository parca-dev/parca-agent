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
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

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
	// BPF map information, such as their size, how many entries they store, etc.
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
	// Native unwinder statistics.
	//
	// These error counters help us track how the unwinder is doing. On errors,
	// the stack is always discarded.
	//
	// The statistics might be slightly off as there's a known race-condition: while
	// the struct is retrieved, its fields may be independently bumped. For example,
	// it's possible that the total samples count will be larger than the sum of all the
	// other stats as it's the first field that's incremented and we might be reading
	// the statistics between that increment and the other field's.
	descNativeUnwinderTotalSamples = prometheus.NewDesc(
		"parca_agent_native_unwinder_samples_total",
		"Total samples.",
		[]string{"unwinder"}, nil,
	)
	descNativeUnwinderSuccess = prometheus.NewDesc(
		"parca_agent_native_unwinder_success_total",
		"Samples that unwound successfully reaching the bottom frame.",
		[]string{"unwinder"}, nil,
	)
	descNativeUnwinderErrors = prometheus.NewDesc(
		"parca_agent_native_unwinder_error_total",
		"There was an error while unwinding the stack.",
		[]string{"reason"}, nil,
	)
)

func (c *bpfMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descBPFMemlock
	ch <- descBPFMapKeySize
	ch <- descBPFMapValueSize
	ch <- descBPFMapMaxEntries

	ch <- descNativeUnwinderTotalSamples
	ch <- descNativeUnwinderSuccess
	ch <- descNativeUnwinderErrors
}

func (c *bpfMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	for _, bpfMetrics := range c.getBPFMetrics() {
		ch <- prometheus.MustNewConstMetric(descBPFMemlock, prometheus.GaugeValue, bpfMetrics.bpfMemlock, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapKeySize, prometheus.GaugeValue, bpfMetrics.bpfMapKeySize, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapValueSize, prometheus.GaugeValue, bpfMetrics.bpfMapValueSize, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapMaxEntries, prometheus.GaugeValue, bpfMetrics.bpfMaxEntry, bpfMetrics.mapName)
	}

	c.collectUnwinderStatistics(ch)
}

func (c *bpfMetricsCollector) getUnwinderStats() unwinderStats {
	stats, err := c.readCounters()
	if err != nil {
		level.Warn(c.logger).Log("msg", "readPerCpuCounter failed", "error", err)
		return unwinderStats{}
	}

	return stats
}

func (c *bpfMetricsCollector) collectUnwinderStatistics(ch chan<- prometheus.Metric) {
	stats := c.getUnwinderStats()
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderTotalSamples, prometheus.CounterValue, float64(stats.Total), "dwarf")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDwarf), "dwarf")

	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorTruncated), "truncated")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorUnsupportedExpression), "unsupported_expression")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorFramePointerAction), "frame_pointer_action")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorUnsupportedCfaRegister), "unsupported_cfa_register")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorCatchall), "catchall")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorShouldNeverHappen), "should_never_happen")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorPcNotCovered), "pc_not_covered")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJitUnupdatedMapping), "jit_unupdated_mapping")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJitMixedModeDisabled), "jit_mixed_mode_disabled")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorPcNotCoveredJit), "pc_not_covered_jit")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJitUnwindingMachinery), "jit_unwnding_machinery")

	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJitFrame), "jit_frame")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJitToDwarf), "jit_to_dwarf")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDwarfToJit), "dwarf_to_jit")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDwarfReachBottom), "dwarf_reach_bottom")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJitReachBottom), "jit_reach_bottom")
}
