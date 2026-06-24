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

//go:build !nonvml

// This file implements the real NVML producer (cgo; requires a dynamically
// linked binary). It collects, per device:
//   - GPU and memory utilization (sampled, with a current-state fallback)
//   - per-process GPU/memory utilization (pid + comm)
//   - power consumption and the static power limit
//   - graphics/SM/memory/video clocks
//   - GPU temperature
//   - PCIe transmit/receive throughput
//
// Each metric carries the device uuid and index; per-process metrics also carry
// pid and comm.
package gpumetrics

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"golang.org/x/sync/errgroup"
)

const (
	attributeClock                        = "clock"
	attributeIndex                        = "index"
	attributeUUID                         = "uuid"
	attributePID                          = "pid"
	attributeComm                         = "comm"
	metricNameGPUClockHertz               = "gpu_clock_hertz"
	metricNameGPUPCIeThroughputCount      = "gpu_pcie_throughput_count"
	metricNameGPUPCIeThroughputReceive    = "gpu_pcie_throughput_receive_bytes"
	metricNameGPUPCIeThroughputTransmit   = "gpu_pcie_throughput_transmit_bytes"
	metricNameGPUPowerLimitWatt           = "gpu_power_limit_watt"
	metricNameGPUPowerWatt                = "gpu_power_watt"
	metricNameGPUTemperatureCelsius       = "gpu_temperature_celsius"
	metricNameGPUUtilizationMemoryPercent = "gpu_utilization_memory_percent"
	metricNameGPUUtilizationPercent       = "gpu_utilization_percent"
)

// Producer collects NVIDIA GPU metrics and implements metricexport.Producer.
type Producer struct {
	devices  []*perDeviceState
	resolver LabelResolver
}

// NewProducer initializes NVML and enumerates the available NVIDIA devices.
// It returns an error if NVML is unavailable (e.g. no driver / no GPU), which
// the caller should treat as "GPU metrics disabled on this node" rather than
// fatal. Use SetLabelResolver to enable per-process container/pod enrichment.
func NewProducer() (*Producer, error) {
	ret := nvml.Init()
	if !errors.Is(ret, nvml.SUCCESS) {
		return nil, fmt.Errorf("failed to initialize NVML library: %s", nvml.ErrorString(ret))
	}
	count, ret := nvml.DeviceGetCount()
	if !errors.Is(ret, nvml.SUCCESS) {
		return nil, fmt.Errorf("failed to get count of Nvidia devices: %s", nvml.ErrorString(ret))
	}
	devices := make([]*perDeviceState, count)
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if !errors.Is(ret, nvml.SUCCESS) {
			return nil, fmt.Errorf("failed to get handle for Nvidia device %d: %s", i, nvml.ErrorString(ret))
		}
		uuid, ret := device.GetUUID()
		if !errors.Is(ret, nvml.SUCCESS) {
			return nil, fmt.Errorf("failed to get UUID for Nvidia device %d: %s", i, nvml.ErrorString(ret))
		}
		powerLimit, ret := nvml.DeviceGetPowerManagementLimit(device)
		if !errors.Is(ret, nvml.SUCCESS) {
			// Not supported on DGX
			if errors.Is(ret, nvml.ERROR_NOT_SUPPORTED) {
				log.WithFields(log.Fields{"device": i, "err": nvml.ErrorString(ret)}).Warn("gpu power limit not supported")
			} else {
				return nil, fmt.Errorf("failed to get power limit for Nvidia device %d: %s", i, nvml.ErrorString(ret))
			}
		}

		devices[i] = &perDeviceState{
			d:          device,
			uuid:       uuid,
			index:      i,
			powerLimit: powerLimit,

			mu: &sync.RWMutex{},
			lastTimestamp: map[string]uint64{
				metricNameGPUPowerWatt:                0,
				metricNameGPUUtilizationMemoryPercent: 0,
				metricNameGPUUtilizationPercent:       0,
				metricNameGPUPowerLimitWatt:           0,
			},
			gauges: map[string]pmetric.Gauge{},
		}
	}
	return &Producer{devices: devices}, nil
}

// DeviceCount reports how many NVIDIA devices were enumerated.
func (p *Producer) DeviceCount() int { return len(p.devices) }

// SetLabelResolver sets the resolver used to enrich per-process metrics with
// container/pod labels. Call before Collect starts; nil disables enrichment.
func (p *Producer) SetLabelResolver(r LabelResolver) { p.resolver = r }

// Collect runs the background collection loops until ctx is cancelled.
func (p *Producer) Collect(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	// GPU + memory utilization (every 5s).
	g.Go(func() error {
		return tickLoop(ctx, 5*time.Second, func() error {
			for _, pds := range p.devices {
				if err := pds.collectUtilization(); err != nil {
					return err
				}
				if err := pds.collectMemoryUtilization(); err != nil {
					return err
				}
			}
			return nil
		})
	})
	// Per-process utilization (every 1s).
	g.Go(func() error {
		return tickLoop(ctx, time.Second, func() error {
			for _, pds := range p.devices {
				if err := pds.collectProcessUtilization(p.resolver); err != nil {
					return err
				}
			}
			return nil
		})
	})
	// Clocks (every 1s).
	g.Go(func() error {
		return tickLoop(ctx, time.Second, func() error {
			for _, pds := range p.devices {
				if err := pds.collectClock(); err != nil {
					return err
				}
			}
			return nil
		})
	})
	// Power (every 1s).
	g.Go(func() error {
		return tickLoop(ctx, time.Second, func() error {
			for _, pds := range p.devices {
				if err := pds.collectPowerConsumption(); err != nil {
					return err
				}
			}
			return nil
		})
	})
	// PCIe throughput (10x/s).
	g.Go(func() error {
		return tickLoop(ctx, time.Second/10, func() error {
			for _, pds := range p.devices {
				if err := pds.collectPCIThroughput(); err != nil {
					return err
				}
			}
			return nil
		})
	})
	// Temperature (every 1s).
	g.Go(func() error {
		return tickLoop(ctx, time.Second, func() error {
			for _, pds := range p.devices {
				if err := pds.collectTemperature(); err != nil {
					return err
				}
			}
			return nil
		})
	})

	return g.Wait()
}

// tickLoop calls fn every interval until ctx is cancelled. A cancelled context
// is a clean shutdown (returns nil), not an error.
func tickLoop(ctx context.Context, interval time.Duration, fn func() error) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := fn(); err != nil {
				return err
			}
		}
	}
}

// Produce moves the metrics collected so far into ms.
func (p *Producer) Produce(ms pmetric.MetricSlice) error {
	for _, device := range p.devices {
		device.mu.Lock()
		for metricName, gauge := range device.gauges {
			m := ms.AppendEmpty()
			m.SetName(metricName)
			m.SetEmptyGauge()
			if gauge.DataPoints().Len() > 0 {
				gauge.MoveTo(m.Gauge())
			}
		}
		device.mu.Unlock()

		// Append the static power-limit metric (read once, never changes).
		m := ms.AppendEmpty()
		m.SetName(metricNameGPUPowerLimitWatt)
		m.SetEmptyGauge()
		dp := m.Gauge().DataPoints().AppendEmpty()
		dp.Attributes().PutStr(attributeUUID, device.uuid)
		dp.Attributes().PutInt(attributeIndex, int64(device.index))
		dp.SetTimestamp(pcommon.Timestamp(time.Now().UnixNano()))
		dp.SetIntValue(int64(device.powerLimit) / 1000) // milliwatts to watts
	}
	return nil
}

type perDeviceState struct {
	d          nvml.Device
	uuid       string
	index      int
	powerLimit uint32

	mu            *sync.RWMutex
	lastTimestamp map[string]uint64
	gauges        map[string]pmetric.Gauge

	// unsupported records NVML capabilities that returned NOT_SUPPORTED so we
	// stop polling them. NOT_SUPPORTED is a static device property (e.g. PCIe
	// throughput on NVLink-C2C parts such as GB10 / DGX Spark, where the GPU
	// isn't behind a PCIe bus), so retrying or warning every tick is just noise.
	unsupported sync.Map // capability string -> struct{}
}

// disableCapability marks an NVML capability unsupported on this device so it is
// no longer collected, logging once at info level.
func (ds *perDeviceState) disableCapability(capability string, fields log.Fields) {
	if _, existed := ds.unsupported.LoadOrStore(capability, struct{}{}); !existed {
		log.WithFields(fields).Infof("%s not supported on this device; disabling its collection", capability)
	}
}

// capabilityDisabled reports whether a capability has been marked unsupported.
func (ds *perDeviceState) capabilityDisabled(capability string) bool {
	_, disabled := ds.unsupported.Load(capability)
	return disabled
}

func (ds *perDeviceState) getLastTimestamp(metric string) uint64 {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.lastTimestamp[metric]
}

func (ds *perDeviceState) appendGauge(metricName string, maxTimestamp uint64, g pmetric.Gauge) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.lastTimestamp[metricName] = maxTimestamp
	if _, found := ds.gauges[metricName]; found {
		g.DataPoints().MoveAndAppendTo(ds.gauges[metricName].DataPoints())
	} else {
		ds.gauges[metricName] = g
	}
}

func (ds *perDeviceState) appendGaugeWithoutTime(metricName string, g pmetric.Gauge) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, found := ds.gauges[metricName]; found {
		g.DataPoints().MoveAndAppendTo(ds.gauges[metricName].DataPoints())
	} else {
		ds.gauges[metricName] = g
	}
}

func (ds *perDeviceState) collectUtilization() error {
	metricName := metricNameGPUUtilizationPercent
	g := pmetric.NewGauge()

	maxTimestamp := ds.getLastTimestamp(metricName)

	sampleType, samples, ret := ds.d.GetSamples(nvml.GPU_UTILIZATION_SAMPLES, maxTimestamp)
	switch {
	case errors.Is(ret, nvml.SUCCESS):
		getValue, err := valueGetter(sampleType)
		if err != nil {
			return err
		}

		sort.Slice(samples, func(i, j int) bool {
			return samples[i].TimeStamp < samples[j].TimeStamp
		})

		offsetNanos := nvmlSampleOffsetNanos(time.Now(), samples)
		for _, s := range samples {
			value := getValue(s.SampleValue).(int64)

			if s.TimeStamp == 0 {
				continue
			}
			if value < 0 || value > 100 { // ignore if below 0% or above 100%
				continue
			}

			maxTimestamp = max(maxTimestamp, s.TimeStamp)

			dp := g.DataPoints().AppendEmpty()
			dp.Attributes().PutStr(attributeUUID, ds.uuid)
			dp.Attributes().PutInt(attributeIndex, int64(ds.index))
			dp.SetTimestamp(pcommon.Timestamp(int64(s.TimeStamp)*1000 + offsetNanos))
			dp.SetIntValue(value)
		}
	case errors.Is(ret, nvml.ERROR_NOT_FOUND):
		// Sample buffer empty (typically when the GPU is idle); fall through
		// to the snapshot fallback below so the series stays continuous.
	default:
		return fmt.Errorf("failed to get GPU_UTILIZATION_SAMPLES: %w", ret)
	}

	if g.DataPoints().Len() == 0 {
		// NVML returned no usable samples — emit a current-state snapshot so
		// the series keeps reporting (e.g. 0% during idle) instead of going dark.
		// maxTimestamp is intentionally not advanced here: it's in NVML's clock
		// domain, not wall clock, so the next GetSamples call must keep it as-is.
		rates, ret := ds.d.GetUtilizationRates()
		if errors.Is(ret, nvml.SUCCESS) {
			ts := time.Now()
			dp := g.DataPoints().AppendEmpty()
			dp.Attributes().PutStr(attributeUUID, ds.uuid)
			dp.Attributes().PutInt(attributeIndex, int64(ds.index))
			dp.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
			dp.SetIntValue(int64(rates.Gpu))
		} else if !errors.Is(ret, nvml.ERROR_NOT_SUPPORTED) {
			log.WithFields(log.Fields{"device": ds.index, "err": nvml.ErrorString(ret)}).Warn("GetUtilizationRates failed")
		}
	}

	ds.appendGauge(metricName, maxTimestamp, g)
	return nil
}

func (ds *perDeviceState) collectMemoryUtilization() error {
	metricName := metricNameGPUUtilizationMemoryPercent
	g := pmetric.NewGauge()

	maxTimestamp := ds.getLastTimestamp(metricName)

	sampleType, samples, ret := ds.d.GetSamples(nvml.MEMORY_UTILIZATION_SAMPLES, maxTimestamp)
	switch {
	case errors.Is(ret, nvml.SUCCESS):
		getValue, err := valueGetter(sampleType)
		if err != nil {
			return err
		}

		sort.Slice(samples, func(i, j int) bool {
			return samples[i].TimeStamp < samples[j].TimeStamp
		})

		offsetNanos := nvmlSampleOffsetNanos(time.Now(), samples)
		for _, s := range samples {
			value := getValue(s.SampleValue).(int64)

			if s.TimeStamp == 0 {
				continue
			}
			if value < 0 || value > 100 { // ignore if below 0% or above 100%
				continue
			}

			maxTimestamp = max(maxTimestamp, s.TimeStamp)
			dp := g.DataPoints().AppendEmpty()
			dp.Attributes().PutStr(attributeUUID, ds.uuid)
			dp.Attributes().PutInt(attributeIndex, int64(ds.index))
			dp.SetTimestamp(pcommon.Timestamp(int64(s.TimeStamp)*1000 + offsetNanos))
			dp.SetIntValue(value)
		}
	case errors.Is(ret, nvml.ERROR_NOT_FOUND):
		// Sample buffer empty; fall through to the snapshot fallback below.
	default:
		return fmt.Errorf("get MEMORY_UTILIZATION_SAMPLES failed %w", ret)
	}

	if g.DataPoints().Len() == 0 {
		// See note in collectUtilization. maxTimestamp is left unchanged.
		rates, ret := ds.d.GetUtilizationRates()
		if errors.Is(ret, nvml.SUCCESS) {
			ts := time.Now()
			dp := g.DataPoints().AppendEmpty()
			dp.Attributes().PutStr(attributeUUID, ds.uuid)
			dp.Attributes().PutInt(attributeIndex, int64(ds.index))
			dp.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
			dp.SetIntValue(int64(rates.Memory))
		} else if !errors.Is(ret, nvml.ERROR_NOT_SUPPORTED) {
			log.WithFields(log.Fields{"device": ds.index, "err": nvml.ErrorString(ret)}).Warn("GetUtilizationRates failed")
		}
	}

	ds.appendGauge(metricName, maxTimestamp, g)
	return nil
}

// putExtraLabels copies resolver-provided labels onto a data point's attributes.
func putExtraLabels(attrs pcommon.Map, extra map[string]string) {
	for k, v := range extra {
		attrs.PutStr(k, v)
	}
}

func (ds *perDeviceState) collectProcessUtilization(resolver LabelResolver) error {
	util := pmetric.NewGauge()
	utilMem := pmetric.NewGauge()

	ts := time.Now()
	computeProcesses, ret := ds.d.GetComputeRunningProcesses()
	if !errors.Is(ret, nvml.SUCCESS) {
		return fmt.Errorf("failed to get compute running processes for %d: %s", ds.index, nvml.ErrorString(ret))
	}

	graphicsProccesses, ret := ds.d.GetGraphicsRunningProcesses()
	if !errors.Is(ret, nvml.SUCCESS) {
		return fmt.Errorf("failed to get graphics running processes for %d: %s", ds.index, nvml.ErrorString(ret))
	}

	if len(computeProcesses) == 0 && len(graphicsProccesses) == 0 {
		return nil
	}

	processes := append(computeProcesses, graphicsProccesses...)

	for _, process := range processes {
		utilization, ret := ds.d.GetProcessUtilization(uint64(process.Pid))
		if !errors.Is(ret, nvml.SUCCESS) {
			// If the process is not found (likely terminated), skip it.
			if errors.Is(ret, nvml.ERROR_NOT_FOUND) || errors.Is(ret, nvml.ERROR_NO_DATA) {
				continue
			}
			return fmt.Errorf("failed to get process utilization for %d - pid: %d - %s", ds.index, process.Pid, nvml.ErrorString(ret))
		}

		processName, ret := nvml.SystemGetProcessName(int(process.Pid)) // could easily be cached
		if !errors.Is(ret, nvml.SUCCESS) {
			if errors.Is(ret, nvml.ERROR_NOT_FOUND) || errors.Is(ret, nvml.ERROR_NO_DATA) {
				continue
			}
			return fmt.Errorf("failed to get process name for %d - pid: %d - %s", ds.index, process.Pid, nvml.ErrorString(ret))
		}

		// Resolve container/pod labels once per process; they're identical
		// across this process's utilization samples.
		var extraLabels map[string]string
		if resolver != nil {
			extraLabels = resolver.LabelsForPID(process.Pid)
		}

		for _, sample := range utilization {
			dpUtil := util.DataPoints().AppendEmpty()
			dpUtil.Attributes().PutStr(attributeUUID, ds.uuid)
			dpUtil.Attributes().PutInt(attributeIndex, int64(ds.index))
			dpUtil.Attributes().PutInt(attributePID, int64(process.Pid))
			dpUtil.Attributes().PutStr(attributeComm, processName)
			putExtraLabels(dpUtil.Attributes(), extraLabels)
			dpUtil.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
			dpUtil.SetIntValue(int64(sample.SmUtil))

			dpMem := utilMem.DataPoints().AppendEmpty()
			dpMem.Attributes().PutStr(attributeUUID, ds.uuid)
			dpMem.Attributes().PutInt(attributeIndex, int64(ds.index))
			dpMem.Attributes().PutInt(attributePID, int64(process.Pid))
			dpMem.Attributes().PutStr(attributeComm, processName)
			putExtraLabels(dpMem.Attributes(), extraLabels)
			dpMem.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
			dpMem.SetIntValue(int64(sample.MemUtil))
		}
	}

	ds.appendGaugeWithoutTime(metricNameGPUUtilizationPercent, util)
	ds.appendGaugeWithoutTime(metricNameGPUUtilizationMemoryPercent, utilMem)
	return nil
}

func (ds *perDeviceState) collectClock() error {
	clockTypes := map[string]nvml.ClockType{
		"graphics": nvml.CLOCK_GRAPHICS,
		"sm":       nvml.CLOCK_SM,
		"mem":      nvml.CLOCK_MEM,
		"video":    nvml.CLOCK_VIDEO,
	}

	g := pmetric.NewGauge()

	for clockName, clockType := range clockTypes {
		capability := "gpu_clock_hertz:" + clockName
		if ds.capabilityDisabled(capability) {
			continue
		}
		ts := time.Now()
		clock, ret := nvml.DeviceGetClockInfo(ds.d, clockType)
		if !errors.Is(ret, nvml.SUCCESS) {
			// Some clock domains aren't exposed on every part; stop polling the
			// ones this device doesn't support rather than appending a bogus 0.
			if errors.Is(ret, nvml.ERROR_NOT_SUPPORTED) {
				ds.disableCapability(capability, log.Fields{"device": ds.index, "clock": clockName})
				continue
			}
			return fmt.Errorf("failed to get clock for %d %s: %s", ds.index, clockName, nvml.ErrorString(ret))
		}
		clock *= 1e6 // MHz to Hertz

		dp := g.DataPoints().AppendEmpty()
		dp.Attributes().PutStr(attributeUUID, ds.uuid)
		dp.Attributes().PutInt(attributeIndex, int64(ds.index))
		dp.Attributes().PutStr(attributeClock, clockName)
		dp.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
		dp.SetIntValue(int64(clock))
	}

	ds.appendGauge(metricNameGPUClockHertz, uint64(time.Now().UnixNano()), g)
	return nil
}

func (ds *perDeviceState) collectPowerConsumption() error {
	metricName := metricNameGPUPowerWatt
	if ds.capabilityDisabled(metricName) {
		return nil
	}
	g := pmetric.NewGauge()

	maxTimestamp := ds.getLastTimestamp(metricName)

	sampleType, samples, ret := ds.d.GetSamples(nvml.TOTAL_POWER_SAMPLES, maxTimestamp)
	if !errors.Is(ret, nvml.SUCCESS) {
		switch {
		case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
			ds.disableCapability(metricName, log.Fields{"device": ds.index, "metric": metricName})
			return nil
		case errors.Is(ret, nvml.ERROR_NOT_FOUND):
			// Sample buffer empty (transient, e.g. idle); skip this tick.
			log.WithField("device", ds.index).Debug("TOTAL_POWER_SAMPLES buffer empty")
			return nil
		default:
			return fmt.Errorf("GetSamples failed %v", ret)
		}
	}
	getValue, err := valueGetter(sampleType)
	if err != nil {
		return err
	}

	sort.Slice(samples, func(i, j int) bool {
		return samples[i].TimeStamp < samples[j].TimeStamp
	})

	offsetNanos := nvmlSampleOffsetNanos(time.Now(), samples)
	for _, s := range samples {
		if s.TimeStamp == 0 {
			continue
		}
		value := getValue(s.SampleValue).(int64) / 1000 // milliwatts to watts
		if value > 10*1000 {                            // ignore if above 10k watt
			continue
		}
		if value < 0 { // ignore negative power consumption
			continue
		}

		maxTimestamp = max(maxTimestamp, s.TimeStamp)

		dp := g.DataPoints().AppendEmpty()
		dp.Attributes().PutStr(attributeUUID, ds.uuid)
		dp.Attributes().PutInt(attributeIndex, int64(ds.index))
		dp.SetTimestamp(pcommon.Timestamp(int64(s.TimeStamp)*1000 + offsetNanos))
		dp.SetIntValue(value)
	}

	ds.appendGauge(metricName, maxTimestamp, g)
	return nil
}

func (ds *perDeviceState) collectTemperature() error {
	metricName := metricNameGPUTemperatureCelsius

	ts := time.Now()
	temp, ret := ds.d.GetTemperature(nvml.TEMPERATURE_GPU)
	if !errors.Is(ret, nvml.SUCCESS) {
		return fmt.Errorf("failed to get temperature for %d: %s", ds.index, nvml.ErrorString(ret))
	}

	g := pmetric.NewGauge()
	dp := g.DataPoints().AppendEmpty()
	dp.Attributes().PutStr(attributeUUID, ds.uuid)
	dp.Attributes().PutInt(attributeIndex, int64(ds.index))
	dp.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
	dp.SetIntValue(int64(temp))

	ds.appendGauge(metricName, uint64(ts.UnixNano()), g)
	return nil
}

var pcieCounters = []nvml.PcieUtilCounter{
	nvml.PCIE_UTIL_TX_BYTES,
	nvml.PCIE_UTIL_RX_BYTES,
	// nvml.PCIE_UTIL_COUNT, // not used until needed
}

func pcieMetricName(counter nvml.PcieUtilCounter) string {
	switch counter {
	case nvml.PCIE_UTIL_TX_BYTES:
		return metricNameGPUPCIeThroughputTransmit
	case nvml.PCIE_UTIL_RX_BYTES:
		return metricNameGPUPCIeThroughputReceive
	case nvml.PCIE_UTIL_COUNT:
		return metricNameGPUPCIeThroughputCount
	}
	return ""
}

func (ds *perDeviceState) collectPCIThroughput() error {
	for _, counter := range pcieCounters {
		metricName := pcieMetricName(counter)
		if ds.capabilityDisabled(metricName) {
			continue
		}
		ts := time.Now()

		tp, ret := ds.d.GetPcieThroughput(counter)
		if !errors.Is(ret, nvml.SUCCESS) {
			// PCIe throughput is unavailable on parts where the GPU isn't behind
			// a PCIe bus (e.g. NVLink-C2C on GB10 / DGX Spark). Stop polling it.
			if errors.Is(ret, nvml.ERROR_NOT_SUPPORTED) {
				ds.disableCapability(metricName, log.Fields{"device": ds.index, "metric": metricName})
				continue
			}
			return fmt.Errorf("failed to get PCIe throughput for %d %d: %s", ds.index, counter, nvml.ErrorString(ret))
		}

		switch counter {
		case nvml.PCIE_UTIL_TX_BYTES, nvml.PCIE_UTIL_RX_BYTES:
			tp *= 1000 // KB/s to bytes/s
		}

		g := pmetric.NewGauge()
		dp := g.DataPoints().AppendEmpty()
		dp.Attributes().PutStr(attributeUUID, ds.uuid)
		dp.Attributes().PutInt(attributeIndex, int64(ds.index))
		dp.SetTimestamp(pcommon.Timestamp(ts.UnixNano()))
		dp.SetIntValue(int64(tp))

		ds.appendGauge(metricName, uint64(ts.UnixNano()), g)
	}

	return nil
}

// nvmlSampleOffsetNanos returns the offset in nanoseconds to add to an NVML
// sample timestamp (microseconds against an unspecified reference clock —
// typically CLOCK_BOOTTIME on Linux drivers) to convert it to wall-clock
// nanoseconds since the Unix epoch. It assumes the most recent sample's
// timestamp is approximately "now" in NVML's clock and anchors against
// wallNow. Returns 0 if there are no usable samples.
func nvmlSampleOffsetNanos(wallNow time.Time, samples []nvml.Sample) int64 {
	var maxTs uint64
	for _, s := range samples {
		if s.TimeStamp > maxTs {
			maxTs = s.TimeStamp
		}
	}
	if maxTs == 0 {
		return 0
	}
	return wallNow.UnixNano() - int64(maxTs)*1000
}

func valueGetter(sampleType nvml.ValueType) (func([8]byte) any, error) {
	switch sampleType {
	case nvml.VALUE_TYPE_DOUBLE:
		return func(val [8]byte) any {
			var value float64
			if err := binary.Read(bytes.NewReader(val[:]), binary.NativeEndian, &value); err != nil {
				// This can never happen unless we've made a programming error.
				panic(err)
			}
			return value
		}, nil
	case nvml.VALUE_TYPE_UNSIGNED_INT, nvml.VALUE_TYPE_UNSIGNED_LONG, nvml.VALUE_TYPE_UNSIGNED_LONG_LONG, nvml.VALUE_TYPE_SIGNED_LONG_LONG, nvml.VALUE_TYPE_SIGNED_INT, nvml.VALUE_TYPE_COUNT:
		return func(val [8]byte) any {
			var value int64
			if err := binary.Read(bytes.NewReader(val[:]), binary.NativeEndian, &value); err != nil {
				// This can never happen unless we've made a programming error.
				panic(err)
			}
			return value
		}, nil
	default:
		return nil, fmt.Errorf("unsupported sample type %v", sampleType)
	}
}
