// Copyright 2022-2024 The Parca Authors
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
	"strconv"
	"unsafe"

	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

// Must be in sync with the BPF program.
type unwinderStats struct {
	TotalRuns                   uint64
	TotalSamples                uint64
	SuccessDWARF                uint64
	ErrorTruncated              uint64
	ErrorUnsupportedExpression  uint64
	ErrorFramePointerAction     uint64
	ErrorUnsupportedCfaRegister uint64
	ErrorCatchall               uint64
	ErrorShouldNeverHappen      uint64
	ErrorPcNotCovered           uint64
	ErrorPcNotCoveredJIT        uint64
	ErrorJITUnupdatedMapping    uint64
	ErrorJITMixedModeDisabled   uint64
	SuccessJITFrame             uint64
	SuccessJITToDWARF           uint64
	SuccessDWARFToJIT           uint64
	SuccessDWARFReachBottom     uint64
	SuccessJITReachBottom       uint64

	EventRequestUnwindInformation  uint64
	EventRequestProcessMappings    uint64
	EventRequestRefreshProcessInfo uint64

	TotalZeroPids     uint64
	TotalKthreads     uint64
	TotalFilterMisses uint64
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
	descProgramRuns = prometheus.NewDesc(
		"parca_agent_bpf_program_runs_total",
		"Total number of times the BPF program has been run without the executing code being only kernel code.",
		nil,
		nil,
	)

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
	descEarlyExitZeroPid = prometheus.NewDesc(
		"parca_agent_bpf_program_miss_zero_pid",
		"Total number of times the BPF program exited early due to a zero pid.",
		nil,
		nil,
	)
	descEarlyExitKThreads = prometheus.NewDesc(
		"parca_agent_bpf_program_miss_kthreads",
		"Total number of times the BPF program exited early due to being a kernel thread.",
		nil,
		nil,
	)
	descEarlyExitFilter = prometheus.NewDesc(
		"parca_agent_bpf_program_miss_filter",
		"Total number of times the BPF program exited early due to process filter miss.",
		nil,
		nil,
	)
)

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descBPFMemlock
	ch <- descBPFMapKeySize
	ch <- descBPFMapValueSize
	ch <- descBPFMapMaxEntries

	ch <- descProgramRuns
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
	ch <- prometheus.MustNewConstMetric(descProgramRuns, prometheus.CounterValue, float64(stats.TotalRuns))
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderTotalSamples, prometheus.CounterValue, float64(stats.TotalSamples), "dwarf")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDWARF), "dwarf")

	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorTruncated), "truncated")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorUnsupportedExpression), "unsupported_expression")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorFramePointerAction), "frame_pointer_action")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorUnsupportedCfaRegister), "unsupported_cfa_register")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorCatchall), "catchall")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorShouldNeverHappen), "should_never_happen")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorPcNotCovered), "pc_not_covered")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorPcNotCoveredJIT), "pc_not_covered_jit")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJITUnupdatedMapping), "jit_unupdated_mapping")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderErrors, prometheus.CounterValue, float64(stats.ErrorJITMixedModeDisabled), "jit_mixed_mode_disabled")

	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJITFrame), "jit_frame")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJITToDWARF), "jit_to_dwarf")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDWARFToJIT), "dwarf_to_jit")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessDWARFReachBottom), "dwarf_reach_bottom")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.SuccessJITReachBottom), "jit_reach_bottom")

	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.EventRequestUnwindInformation), "event_request_unwind_info")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.EventRequestProcessMappings), "event_request_process_mappings")
	ch <- prometheus.MustNewConstMetric(descNativeUnwinderSuccess, prometheus.CounterValue, float64(stats.EventRequestRefreshProcessInfo), "event_request_refresh_process_info")

	ch <- prometheus.MustNewConstMetric(descEarlyExitZeroPid, prometheus.CounterValue, float64(stats.TotalZeroPids))
	ch <- prometheus.MustNewConstMetric(descEarlyExitKThreads, prometheus.CounterValue, float64(stats.TotalKthreads))
	ch <- prometheus.MustNewConstMetric(descEarlyExitFilter, prometheus.CounterValue, float64(stats.TotalFilterMisses))
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
		bpfMapFd := strconv.Itoa(bpfMap.FileDescriptor())

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

		total.TotalRuns += partial.TotalRuns
		total.TotalSamples += partial.TotalSamples
		total.SuccessDWARF += partial.SuccessDWARF
		total.ErrorTruncated += partial.ErrorTruncated
		total.ErrorUnsupportedExpression += partial.ErrorUnsupportedExpression
		total.ErrorFramePointerAction += partial.ErrorFramePointerAction
		total.ErrorUnsupportedCfaRegister += partial.ErrorUnsupportedCfaRegister
		total.ErrorCatchall += partial.ErrorCatchall
		total.ErrorShouldNeverHappen += partial.ErrorShouldNeverHappen
		total.ErrorPcNotCovered += partial.ErrorPcNotCovered
		total.ErrorPcNotCoveredJIT += partial.ErrorPcNotCoveredJIT
		total.ErrorJITUnupdatedMapping += partial.ErrorJITUnupdatedMapping
		total.ErrorJITMixedModeDisabled += partial.ErrorJITMixedModeDisabled
		total.SuccessJITFrame += partial.SuccessJITFrame
		total.SuccessJITToDWARF += partial.SuccessJITToDWARF
		total.SuccessDWARFToJIT += partial.SuccessDWARFToJIT
		total.SuccessDWARFReachBottom += partial.SuccessDWARFReachBottom
		total.SuccessJITReachBottom += partial.SuccessJITReachBottom

		total.EventRequestUnwindInformation += partial.EventRequestUnwindInformation
		total.EventRequestProcessMappings += partial.EventRequestProcessMappings
		total.EventRequestRefreshProcessInfo += partial.EventRequestRefreshProcessInfo

		total.TotalZeroPids += partial.TotalZeroPids
		total.TotalKthreads += partial.TotalKthreads
		total.TotalFilterMisses += partial.TotalFilterMisses

	}

	return total, nil
}
