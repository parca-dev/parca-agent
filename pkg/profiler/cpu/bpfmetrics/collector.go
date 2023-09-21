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

package bpfmetrics

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

// Must be in sync with the BPF program.
type unwinderStats struct {
	Total                       uint64
	SuccessDwarf                uint64
	ErrorTruncated              uint64
	ErrorUnsupportedExpression  uint64
	ErrorFramePointerAction     uint64
	ErrorUnsupportedCfaRegister uint64
	ErrorCatchall               uint64
	ErrorShouldNeverHappen      uint64
	ErrorPcNotCovered           uint64
	ErrorPcNotCoveredJit        uint64
	ErrorJitUnupdatedMapping    uint64
	ErrorJitMixedModeDisabled   uint64
	SuccessJitFrame             uint64
	SuccessJitToDwarf           uint64
	SuccessDwarfToJit           uint64
	SuccessDwarfReachBottom     uint64
	SuccessJitReachBottom       uint64
}

type bpfMetrics struct {
	mapName         string
	bpfMapKeySize   float64
	bpfMapValueSize float64
	bpfMaxEntry     float64
	bpfMemlock      float64
}

type Collector struct {
	logger             log.Logger
	m                  *libbpf.Module
	perCPUStatsMapName string
	pid                int
}

func NewCollector(logger log.Logger, m *libbpf.Module, perCPUStatsMapName string, pid int) *Collector {
	return &Collector{
		logger:             logger,
		m:                  m,
		perCPUStatsMapName: perCPUStatsMapName,
		pid:                pid,
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

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descBPFMemlock
	ch <- descBPFMapKeySize
	ch <- descBPFMapValueSize
	ch <- descBPFMapMaxEntries

	ch <- descNativeUnwinderTotalSamples
	ch <- descNativeUnwinderSuccess
	ch <- descNativeUnwinderErrors
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, bpfMetrics := range c.getBPFMetrics() {
		ch <- prometheus.MustNewConstMetric(descBPFMemlock, prometheus.GaugeValue, bpfMetrics.bpfMemlock, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapKeySize, prometheus.GaugeValue, bpfMetrics.bpfMapKeySize, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapValueSize, prometheus.GaugeValue, bpfMetrics.bpfMapValueSize, bpfMetrics.mapName)
		ch <- prometheus.MustNewConstMetric(descBPFMapMaxEntries, prometheus.GaugeValue, bpfMetrics.bpfMaxEntry, bpfMetrics.mapName)
	}

	c.collectUnwinderStatistics(ch)
}

func (c *Collector) getUnwinderStats() unwinderStats {
	stats, err := c.readCounters()
	if err != nil {
		level.Warn(c.logger).Log("msg", "readPerCpuCounter failed", "error", err)
		return unwinderStats{}
	}

	return stats
}

func (c *Collector) collectUnwinderStatistics(ch chan<- prometheus.Metric) {
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
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorPcNotCoveredJit), "pc_not_covered_jit")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJitUnupdatedMapping), "jit_unupdated_mapping")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJitMixedModeDisabled), "jit_mixed_mode_disabled")

	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJitFrame), "jit_frame")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJitToDwarf), "jit_to_dwarf")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDwarfToJit), "dwarf_to_jit")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDwarfReachBottom), "dwarf_reach_bottom")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJitReachBottom), "jit_reach_bottom")
}

func (c *Collector) getBPFMetrics() []*bpfMetrics {
	var bpfMapsNames []string
	//nolint: prealloc
	var bpfMetricArray []*bpfMetrics

	it := c.m.Iterator()

	for {
		mapBpf := it.NextMap()
		if mapBpf != nil {
			bpfMapsNames = append(bpfMapsNames, mapBpf.Name())
		} else {
			break
		}
	}

	for _, mapName := range bpfMapsNames {
		bpfMap, err := c.m.GetMap(mapName)
		if err != nil {
			level.Debug(c.logger).Log("msg", "error fetching bpf map", "err", err)
			continue
		}

		bpfMaxEntry := float64(bpfMap.MaxEntries())
		bpfMapKeySize := float64(bpfMap.KeySize())
		bpfMapValueSize := float64(bpfMap.ValueSize())
		bpfMapFd := fmt.Sprint(bpfMap.FileDescriptor())

		path := fmt.Sprintf("/proc/%d/fdinfo/", c.pid) + bpfMapFd
		data, err := readFileNoStat(path)
		if err != nil {
			level.Debug(c.logger).Log("msg", "Unable to read fds for agent process", "agent_pid", c.pid, "err", err)
		}

		bpfMemlock, err := FdInfoMemlock(c.logger, data)
		if err != nil {
			level.Debug(c.logger).Log("msg", "error getting memory locked for file descriptor", "err", err)
		}

		bpfMetricArray = append(bpfMetricArray,
			&bpfMetrics{
				mapName:         mapName,
				bpfMapKeySize:   bpfMapKeySize,
				bpfMapValueSize: bpfMapValueSize,
				bpfMaxEntry:     bpfMaxEntry,
				bpfMemlock:      float64(bpfMemlock),
			},
		)
	}
	return bpfMetricArray
}

// readPerCpuCounter reads the value of the given key from the per CPU stats map.
func (c *Collector) readCounters() (unwinderStats, error) {
	numCpus, err := libbpf.NumPossibleCPUs()
	if err != nil {
		return unwinderStats{}, fmt.Errorf("NumPossibleCPUs failed: %w", err)
	}
	sizeOfUnwinderStats := int(unsafe.Sizeof(unwinderStats{}))

	statsMap, err := c.m.GetMap(c.perCPUStatsMapName)
	if err != nil {
		return unwinderStats{}, err
	}

	valuesBytes := make([]byte, sizeOfUnwinderStats*numCpus)
	key := uint32(0)
	if err := statsMap.GetValueReadInto(unsafe.Pointer(&key), &valuesBytes); err != nil { // nolint:staticcheck
		return unwinderStats{}, fmt.Errorf("get count values: %w", err)
	}

	total := unwinderStats{}

	for i := 0; i < numCpus; i++ {
		partial := unwinderStats{}
		cpuStats := valuesBytes[i*sizeOfUnwinderStats : i*sizeOfUnwinderStats+sizeOfUnwinderStats]
		err := binary.Read(bytes.NewBuffer(cpuStats), binary.LittleEndian, &partial)
		if err != nil {
			level.Error(c.logger).Log("msg", "error reading unwinder stats ", "err", err)
		}

		total.Total += partial.Total
		total.SuccessDwarf += partial.SuccessDwarf
		total.ErrorTruncated += partial.ErrorTruncated
		total.ErrorUnsupportedExpression += partial.ErrorUnsupportedExpression
		total.ErrorFramePointerAction += partial.ErrorFramePointerAction
		total.ErrorUnsupportedCfaRegister += partial.ErrorUnsupportedCfaRegister
		total.ErrorCatchall += partial.ErrorCatchall
		total.ErrorShouldNeverHappen += partial.ErrorShouldNeverHappen
		total.ErrorPcNotCovered += partial.ErrorPcNotCovered
		total.ErrorPcNotCoveredJit += partial.ErrorPcNotCoveredJit
		total.ErrorJitUnupdatedMapping += partial.ErrorJitUnupdatedMapping
		total.ErrorJitMixedModeDisabled += partial.ErrorJitMixedModeDisabled
		total.SuccessJitFrame += partial.SuccessJitFrame
		total.SuccessJitToDwarf += partial.SuccessJitToDwarf
		total.SuccessDwarfToJit += partial.SuccessDwarfToJit
		total.SuccessDwarfReachBottom += partial.SuccessDwarfReachBottom
		total.SuccessJitReachBottom += partial.SuccessJitReachBottom
	}

	return total, nil
}
