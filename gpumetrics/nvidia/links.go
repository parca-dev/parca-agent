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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/parca-dev/parca-agent/gpumetrics"
)

// The link capacity metrics say how much of a link's bandwidth its throughput
// uses: nvidia.gpu.pcie.throughput against nvidia.gpu.pcie.bandwidth.limit,
// and nvidia.gpu.nvlink.throughput against nvidia.gpu.nvlink.bandwidth.limit.

// pcieThroughputWindow is the interval GetPcieThroughput measures over.
const pcieThroughputWindow = 20 * time.Millisecond

// pcieLaneBandwidth returns the usable bandwidth of one PCIe lane in one
// direction, in bytes/s, at generation gen: the transfer rate less line
// encoding. 0 if gen is unknown.
func pcieLaneBandwidth(gen int) int64 {
	const giga = 1_000_000_000
	switch gen {
	case 1:
		return 2.5 * giga * 8 / 10 / 8 // 8b/10b
	case 2:
		return 5 * giga * 8 / 10 / 8
	case 3:
		return 8 * giga * 128 / 130 / 8 // 128b/130b
	case 4:
		return 16 * giga * 128 / 130 / 8
	case 5:
		return 32 * giga * 128 / 130 / 8
	case 6:
		return 64 * giga * 236 / 256 / 8 // FLIT: 236 TLP bytes per 256
	}
	return 0
}

// collectPCIeLink reports the generation and width the PCIe link runs at, and
// the bandwidth they allow. Links train down when the GPU idles, so this is
// what the link allows now, not what the slot could.
func (c *Collector) collectPCIeLink(d *device) error {
	const capability = "pcie link"
	if d.disabled(capability) {
		return nil
	}
	gen, ret := d.d.GetCurrPcieLinkGeneration()
	var width int
	if errors.Is(ret, nvml.SUCCESS) {
		width, ret = d.d.GetCurrPcieLinkWidth()
	}
	switch {
	case errors.Is(ret, nvml.SUCCESS):
	case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		// No PCIe link, e.g. NVLink-C2C on GB10.
		d.disable(capability)
		return nil
	default:
		return fmt.Errorf("get pcie link: %s", nvml.ErrorString(ret))
	}

	ts := pcommon.NewTimestampFromTime(time.Now())
	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		put := func(metric string, v int64) {
			dp := b.Points(metric).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.SetTimestamp(ts)
			dp.SetIntValue(v)
		}
		put(gpumetrics.MetricPCIeLinkGeneration, int64(gen))
		put(gpumetrics.MetricPCIeLinkWidth, int64(width))
		if lane := pcieLaneBandwidth(gen); lane > 0 && width > 0 {
			put(gpumetrics.MetricPCIeBandwidthLimit, lane*int64(width))
		}
	})
	return nil
}

// collectNVLink reports how many NVLinks are active and the bandwidth they
// allow. Where GPM doesn't report NVLink throughput (before Hopper), it also
// reports the throughput from NVML's per-link data counters, averaged since
// the previous reading.
func (c *Collector) collectNVLink(d *device) error {
	const capability, throughputCapability = "nvlink", "nvlink throughput"
	if len(d.nvlinks) == 0 || d.disabled(capability) {
		return nil
	}
	var active []int
	for _, link := range d.nvlinks {
		state, ret := d.d.GetNvLinkState(link)
		switch {
		case errors.Is(ret, nvml.SUCCESS):
		case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
			d.disable(capability)
			return nil
		default:
			return fmt.Errorf("get nvlink %d state: %s", link, nvml.ErrorString(ret))
		}
		if state == nvml.FEATURE_ENABLED {
			active = append(active, link)
		}
	}

	values := []nvml.FieldValue{{FieldId: nvml.FI_DEV_NVLINK_SPEED_MBPS_COMMON}}
	throughput := len(active) > 0 && !d.gpmNVLink.Load() && !d.disabled(throughputCapability)
	if throughput {
		for _, link := range active {
			values = append(values,
				nvml.FieldValue{FieldId: nvml.FI_DEV_NVLINK_THROUGHPUT_DATA_TX, ScopeId: uint32(link)},
				nvml.FieldValue{FieldId: nvml.FI_DEV_NVLINK_THROUGHPUT_DATA_RX, ScopeId: uint32(link)})
		}
	}
	ret := d.d.GetFieldValues(values)
	now := time.Now()
	if !errors.Is(ret, nvml.SUCCESS) {
		d.nvlinkRead = time.Time{}
		return fmt.Errorf("get nvlink field values: %s", nvml.ErrorString(ret))
	}
	speedMBps, speedRet := fieldResult(values[0])

	// The counters are cumulative KiB per link.
	var tx, rx uint64
	for _, fv := range values[1:] {
		v, ret := fieldResult(fv)
		if !errors.Is(ret, nvml.SUCCESS) {
			if errors.Is(ret, nvml.ERROR_NOT_SUPPORTED) {
				d.disable(throughputCapability)
			}
			throughput = false
			break
		}
		if fv.FieldId == nvml.FI_DEV_NVLINK_THROUGHPUT_DATA_TX {
			tx += v
		} else {
			rx += v
		}
	}
	// A rate needs a previous reading over the same links, and the counters
	// not to have reset or wrapped since.
	prevTX, prevRX, prevRead := d.nvlinkTX, d.nvlinkRX, d.nvlinkRead
	rate := throughput && !prevRead.IsZero() && slices.Equal(active, d.nvlinkActive) &&
		tx >= prevTX && rx >= prevRX && now.After(prevRead)
	if throughput {
		d.nvlinkTX, d.nvlinkRX, d.nvlinkRead, d.nvlinkActive = tx, rx, now, active
	} else {
		d.nvlinkRead = time.Time{}
	}

	ts := pcommon.NewTimestampFromTime(now)
	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		dp := b.Points(gpumetrics.MetricNVLinkLinkCount).AppendEmpty()
		d.PutAttrs(dp.Attributes())
		dp.SetTimestamp(ts)
		dp.SetIntValue(int64(len(active)))

		if errors.Is(speedRet, nvml.SUCCESS) && speedMBps > 0 {
			dp := b.Points(gpumetrics.MetricNVLinkBandwidthLimit).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.SetTimestamp(ts)
			dp.SetIntValue(int64(len(active)) * int64(speedMBps) * 1_000_000)
		}

		if !rate {
			return
		}
		start := pcommon.NewTimestampFromTime(prevRead)
		seconds := now.Sub(prevRead).Seconds()
		for _, dir := range []struct {
			name  string
			bytes uint64
		}{{"transmit", (tx - prevTX) * 1024}, {"receive", (rx - prevRX) * 1024}} {
			dp := b.Points(gpumetrics.MetricNVLinkThroughput).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.Attributes().PutStr(gpumetrics.AttrNetworkIODirection, dir.name)
			dp.SetStartTimestamp(start)
			dp.SetTimestamp(ts)
			dp.SetIntValue(int64(float64(dir.bytes) / seconds))
		}
	})
	return nil
}

// fieldUint reads one NVML field value of d.
func (d *device) fieldUint(field uint32, scope uint32) (uint64, nvml.Return) {
	values := []nvml.FieldValue{{FieldId: field, ScopeId: scope}}
	if ret := d.d.GetFieldValues(values); !errors.Is(ret, nvml.SUCCESS) {
		return 0, ret
	}
	return fieldResult(values[0])
}

// fieldResult returns a field value read by GetFieldValues as an unsigned
// integer, or the error NVML reported for it.
func fieldResult(fv nvml.FieldValue) (uint64, nvml.Return) {
	if ret := nvml.Return(fv.NvmlReturn); !errors.Is(ret, nvml.SUCCESS) {
		return 0, ret
	}
	v := fv.Value[:]
	switch nvml.ValueType(fv.ValueType) {
	case nvml.VALUE_TYPE_UNSIGNED_INT:
		return uint64(binary.NativeEndian.Uint32(v)), nvml.SUCCESS
	case nvml.VALUE_TYPE_UNSIGNED_LONG, nvml.VALUE_TYPE_UNSIGNED_LONG_LONG:
		return binary.NativeEndian.Uint64(v), nvml.SUCCESS
	case nvml.VALUE_TYPE_SIGNED_INT:
		if i := int32(binary.NativeEndian.Uint32(v)); i >= 0 {
			return uint64(i), nvml.SUCCESS
		}
	case nvml.VALUE_TYPE_SIGNED_LONG_LONG:
		if i := int64(binary.NativeEndian.Uint64(v)); i >= 0 {
			return uint64(i), nvml.SUCCESS
		}
	case nvml.VALUE_TYPE_DOUBLE:
		if f := math.Float64frombits(binary.NativeEndian.Uint64(v)); f >= 0 {
			return uint64(f), nvml.SUCCESS
		}
	}
	return 0, nvml.ERROR_UNKNOWN
}
