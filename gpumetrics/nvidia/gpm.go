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

package nvidia

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/parca-dev/parca-agent/gpumetrics"
)

// GPM (GPU Performance Monitoring, Hopper and newer) computes metrics from
// the hardware counters between two samples: how many SMs were busy, which
// execution pipes they used, and how much DRAM and link bandwidth was used.
// Unlike hw.gpu.utilization, which only says whether any kernel was running,
// these say how much of the GPU the work used. Each point covers the interval
// between its two samples: StartTimestamp to Timestamp.

// gpmMinInterval keeps samples further apart than NVML's 100 ms minimum, in
// case the ticker delivers a delayed tick right after the previous one.
const gpmMinInterval = 200 * time.Millisecond

const mibPerSec = 1 << 20 // MiB/s to By/s

// gpmMetric maps a GPM metric to the data point it is reported as.
type gpmMetric struct {
	id     nvml.GpmMetricId
	metric string
	// attrKey/attrValue, if set, distinguish this point within metric.
	attrKey, attrValue string
	// scale converts NVML's value: percentages to fractions, MiB/s to By/s.
	scale float64
}

func pipe(id nvml.GpmMetricId, name string) gpmMetric {
	return gpmMetric{id, gpumetrics.MetricPipeUtilization, gpumetrics.AttrPipe, name, 0.01}
}

func throughput(id nvml.GpmMetricId, metric, direction string) gpmMetric {
	return gpmMetric{id, metric, gpumetrics.AttrNetworkIODirection, direction, mibPerSec}
}

var gpmMetrics = []gpmMetric{
	{nvml.GPM_METRIC_SM_UTIL, gpumetrics.MetricSMUtilization, "", "", 0.01},
	{nvml.GPM_METRIC_SM_OCCUPANCY, gpumetrics.MetricSMOccupancy, "", "", 0.01},
	{nvml.GPM_METRIC_DRAM_BW_UTIL, gpumetrics.MetricDRAMBandwidthUtilization, "", "", 0.01},
	pipe(nvml.GPM_METRIC_ANY_TENSOR_UTIL, "tensor"),
	pipe(nvml.GPM_METRIC_HMMA_TENSOR_UTIL, "tensor_hmma"),
	pipe(nvml.GPM_METRIC_IMMA_TENSOR_UTIL, "tensor_imma"),
	pipe(nvml.GPM_METRIC_DMMA_TENSOR_UTIL, "tensor_dmma"),
	pipe(nvml.GPM_METRIC_DFMA_TENSOR_UTIL, "tensor_dfma"),
	pipe(nvml.GPM_METRIC_FP16_UTIL, "fp16"),
	pipe(nvml.GPM_METRIC_FP32_UTIL, "fp32"),
	pipe(nvml.GPM_METRIC_FP64_UTIL, "fp64"),
	pipe(nvml.GPM_METRIC_INTEGER_UTIL, "integer"),
	throughput(nvml.GPM_METRIC_PCIE_TX_PER_SEC, gpumetrics.MetricPCIeThroughput, "transmit"),
	throughput(nvml.GPM_METRIC_PCIE_RX_PER_SEC, gpumetrics.MetricPCIeThroughput, "receive"),
	throughput(nvml.GPM_METRIC_NVLINK_TOTAL_TX_PER_SEC, gpumetrics.MetricNVLinkThroughput, "transmit"),
	throughput(nvml.GPM_METRIC_NVLINK_TOTAL_RX_PER_SEC, gpumetrics.MetricNVLinkThroughput, "receive"),
	throughput(nvml.GPM_METRIC_C2C_DATA_TX_PER_SEC, gpumetrics.MetricC2CThroughput, "transmit"),
	throughput(nvml.GPM_METRIC_C2C_DATA_RX_PER_SEC, gpumetrics.MetricC2CThroughput, "receive"),
}

// gpmState is a device's GPM sampling state, touched only by the gpm loop.
type gpmState struct {
	// metrics are the metrics still collected: one NVML reports as
	// unsupported on the device is dropped.
	metrics []gpmMetric
	// prev and cur are the two samples; prev holds the previous reading,
	// taken at prevTime, once hasPrev is set.
	prev, cur nvml.GpmSample
	prevTime  time.Time
	hasPrev   bool
}

// newGPMState returns d's GPM state, or nil if GPM doesn't apply to it.
func newGPMState(d nvml.Device, index int) *gpmState {
	support, ret := d.GpmQueryDeviceSupport()
	if !errors.Is(ret, nvml.SUCCESS) || support.IsSupportedDevice == 0 {
		// Say why the GPM metrics are missing, e.g. on GB10.
		reason := "not supported on this device"
		if !errors.Is(ret, nvml.SUCCESS) {
			reason = nvml.ErrorString(ret)
		}
		slog.Info("gpu performance monitoring not collected", "device", index, "reason", reason)
		return nil
	}
	// With MIG enabled, the parent device's counters mix every instance's
	// work, and per-instance sampling (GpmMigSampleGet) isn't implemented.
	if mode, _, ret := d.GetMigMode(); errors.Is(ret, nvml.SUCCESS) && mode == nvml.DEVICE_MIG_ENABLE {
		slog.Info("gpu performance monitoring not collected: MIG is enabled", "device", index)
		return nil
	}
	return &gpmState{metrics: gpmMetrics}
}

// free releases the samples; s may be nil.
func (s *gpmState) free() {
	if s == nil {
		return
	}
	for _, sample := range []nvml.GpmSample{s.prev, s.cur} {
		if sample != nil {
			sample.Free()
		}
	}
	s.prev, s.cur, s.hasPrev = nil, nil, false
}

// collectGPM takes a GPM sample and reports the metrics between it and the
// previous one.
func (c *Collector) collectGPM(d *device) error {
	const capability = "gpm"
	s := d.gpm
	if s == nil || len(s.metrics) == 0 || d.disabled(capability) {
		return nil
	}
	if s.prev == nil {
		var ret nvml.Return
		if s.prev, ret = nvml.GpmSampleAlloc(); !errors.Is(ret, nvml.SUCCESS) {
			s.prev = nil
			return fmt.Errorf("allocate gpm sample: %s", nvml.ErrorString(ret))
		}
		if s.cur, ret = nvml.GpmSampleAlloc(); !errors.Is(ret, nvml.SUCCESS) {
			s.cur = nil
			s.free()
			return fmt.Errorf("allocate gpm sample: %s", nvml.ErrorString(ret))
		}
	}
	if s.hasPrev && time.Since(s.prevTime) < gpmMinInterval {
		return nil
	}

	ret := d.d.GpmSampleGet(s.cur)
	now := time.Now()
	switch {
	case errors.Is(ret, nvml.SUCCESS):
	case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		d.disable(capability)
		s.free()
		return nil
	default:
		// The next sample starts over; one interval is lost.
		s.hasPrev = false
		return fmt.Errorf("get gpm sample: %s", nvml.ErrorString(ret))
	}
	if !s.hasPrev {
		s.prev, s.cur, s.prevTime, s.hasPrev = s.cur, s.prev, now, true
		return nil
	}

	get := nvml.GpmMetricsGetType{
		NumMetrics: uint32(len(s.metrics)),
		Sample1:    s.prev,
		Sample2:    s.cur,
	}
	for i, m := range s.metrics {
		get.Metrics[i].MetricId = uint32(m.id)
	}
	ret = nvml.GpmMetricsGet(&get)
	start := s.prevTime
	s.prev, s.cur, s.prevTime = s.cur, s.prev, now
	if !errors.Is(ret, nvml.SUCCESS) {
		return fmt.Errorf("get gpm metrics: %s", nvml.ErrorString(ret))
	}
	c.recordGPM(d, start, now, get.Metrics[:get.NumMetrics])
	return nil
}

// recordGPM records the results of one GpmMetricsGet over [start, end], in
// the order of d.gpm.metrics, and stops collecting the metrics the device
// doesn't support.
func (c *Collector) recordGPM(d *device, start, end time.Time, results []nvml.GpmMetric) {
	s := d.gpm
	startTS, endTS := pcommon.NewTimestampFromTime(start), pcommon.NewTimestampFromTime(end)
	kept := make([]gpmMetric, 0, len(s.metrics))
	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		for i, m := range s.metrics {
			r := results[i]
			switch ret := nvml.Return(r.NvmlReturn); {
			case errors.Is(ret, nvml.SUCCESS):
			case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
				slog.Info("gpm metric not supported on this device; disabling its collection",
					"metric", m.metric, "attribute", m.attrValue, "device", d.Index)
				continue
			default:
				kept = append(kept, m)
				continue
			}
			kept = append(kept, m)
			if m.metric == gpumetrics.MetricPCIeThroughput {
				d.gpmPCIe.Store(true)
			}
			dp := b.Points(m.metric).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			if m.attrKey != "" {
				dp.Attributes().PutStr(m.attrKey, m.attrValue)
			}
			dp.SetStartTimestamp(startTS)
			dp.SetTimestamp(endTS)
			if m.scale == mibPerSec {
				// Integer bytes/s, like the legacy PCIe reading.
				dp.SetIntValue(int64(r.Value * m.scale))
			} else {
				dp.SetDoubleValue(r.Value * m.scale)
			}
		}
	})
	s.metrics = kept
}
