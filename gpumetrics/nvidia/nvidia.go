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

// This file implements the NVML collectors (cgo; requires a dynamically linked
// binary). Per device:
//   - hw.gpu.utilization and nvidia.gpu.memory_copy.utilization (sampled,
//     with a current-state fallback)
//   - hw.gpu.memory.usage, hw.gpu.memory.limit, hw.gpu.memory.utilization
//   - hw.power and nvidia.gpu.power.limit
//   - hw.temperature
//   - nvidia.gpu.clock.speed per clock domain
//   - nvidia.gpu.pcie.throughput per direction
//
// and per process, on the process's own resource:
//   - nvidia.gpu.process.utilization
//   - nvidia.gpu.process.memory_copy.utilization
//
// It is kept apart from package gpumetrics so that only parca-agent built with
// the gpumetrics tag links go-nvml: binaries that do must bind lazily (see
// build-gpu in the Makefile), which plain `go test` binaries don't.
package nvidia

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"golang.org/x/sync/errgroup"

	"github.com/parca-dev/parca-agent/internal/log"

	"github.com/parca-dev/parca-agent/gpumetrics"
)

// device is one NVIDIA GPU.
type device struct {
	gpumetrics.GPU
	d nvml.Device
	// powerLimitMilliwatts is 0 when the device doesn't report one.
	powerLimitMilliwatts uint32

	// The newest sample timestamp already reported per NVML sampling query,
	// in NVML's clock (microseconds); the next query asks only for newer
	// samples. Each is touched by a single collection loop.
	lastUtilization uint64
	lastMemoryCopy  uint64
	lastPower       uint64
	lastProcess     uint64

	// unsupported records NVML capabilities that returned NOT_SUPPORTED so we
	// stop polling them. NOT_SUPPORTED is a static device property (e.g. PCIe
	// throughput on NVLink-C2C parts such as GB10 / DGX Spark, where the GPU
	// isn't behind a PCIe bus), so retrying or warning every tick is just noise.
	unsupported sync.Map // capability string -> struct{}
}

// disable marks an NVML capability unsupported on this device so it is no
// longer collected, logging once.
func (d *device) disable(capability string) {
	if _, existed := d.unsupported.LoadOrStore(capability, struct{}{}); !existed {
		slog.Info("nvml capability not supported on this device; disabling its collection",
			"capability", capability, "device", d.Index)
	}
}

func (d *device) disabled(capability string) bool {
	_, ok := d.unsupported.Load(capability)
	return ok
}

// Collector collects NVIDIA GPU metrics via NVML into a gpumetrics.Producer.
type Collector struct {
	devices []*device
	rec     *gpumetrics.Producer
}

// NewCollector initializes NVML and enumerates the available NVIDIA devices.
// It returns an error if NVML is unavailable (e.g. no driver / no GPU), which
// the caller should treat as "GPU metrics disabled on this node" rather than
// fatal.
func NewCollector() (*Collector, error) {
	ret := nvml.Init()
	if !errors.Is(ret, nvml.SUCCESS) {
		return nil, fmt.Errorf("failed to initialize NVML library: %s", nvml.ErrorString(ret))
	}
	count, ret := nvml.DeviceGetCount()
	if !errors.Is(ret, nvml.SUCCESS) {
		return nil, fmt.Errorf("failed to get count of Nvidia devices: %s", nvml.ErrorString(ret))
	}
	driverVersion, ret := nvml.SystemGetDriverVersion()
	if !errors.Is(ret, nvml.SUCCESS) {
		driverVersion = ""
	}

	devices := make([]*device, count)
	for i := range count {
		d, ret := nvml.DeviceGetHandleByIndex(i)
		if !errors.Is(ret, nvml.SUCCESS) {
			return nil, fmt.Errorf("failed to get handle for Nvidia device %d: %s", i, nvml.ErrorString(ret))
		}
		uuid, ret := d.GetUUID()
		if !errors.Is(ret, nvml.SUCCESS) {
			return nil, fmt.Errorf("failed to get UUID for Nvidia device %d: %s", i, nvml.ErrorString(ret))
		}
		model, ret := d.GetName()
		if !errors.Is(ret, nvml.SUCCESS) {
			model = ""
		}
		powerLimit, ret := d.GetPowerManagementLimit()
		if !errors.Is(ret, nvml.SUCCESS) {
			// Not supported on DGX, among others.
			slog.Info("gpu power limit unavailable", "device", i, "err", nvml.ErrorString(ret))
			powerLimit = 0
		}

		devices[i] = &device{
			GPU: gpumetrics.GPU{
				Index:         i,
				UUID:          uuid,
				Model:         model,
				DriverVersion: driverVersion,
			},
			d:                    d,
			powerLimitMilliwatts: powerLimit,
		}
	}
	return &Collector{devices: devices}, nil
}

// DeviceCount reports how many NVIDIA devices were enumerated.
func (c *Collector) DeviceCount() int { return len(c.devices) }

// Collect runs the background collection loops, recording into rec, until ctx
// is cancelled. A failing collector is logged and retried on its next tick
// rather than stopping collection.
func (c *Collector) Collect(ctx context.Context, rec *gpumetrics.Producer) error {
	c.rec = rec
	g, ctx := errgroup.WithContext(ctx)
	loop := func(name string, interval time.Duration, collectors ...func(*device) error) {
		g.Go(func() error {
			tickLoop(ctx, name, interval, func() error {
				var errs []error
				for _, d := range c.devices {
					for _, collect := range collectors {
						if err := collect(d); err != nil {
							errs = append(errs, fmt.Errorf("device %d: %w", d.Index, err))
						}
					}
				}
				return errors.Join(errs...)
			})
			return nil
		})
	}

	loop("utilization", 5*time.Second,
		c.collectUtilization, c.collectMemoryCopyUtilization, c.collectMemory, c.collectPowerLimit)
	loop("process utilization", time.Second, c.collectProcesses)
	loop("clocks", time.Second, c.collectClocks)
	loop("power", time.Second, c.collectPower)
	loop("temperature", time.Second, c.collectTemperature)
	loop("pcie throughput", time.Second/10, c.collectPCIeThroughput)

	return g.Wait()
}

// tickLoop calls fn every interval until ctx is cancelled. Errors are logged
// when they first appear or change, and once when they clear, so a persistent
// failure doesn't log every tick.
func tickLoop(ctx context.Context, name string, interval time.Duration, fn func() error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := fn()
			switch {
			case err != nil && err.Error() != lastErr:
				slog.Warn("collecting gpu metrics failed", "collector", name, "err", err)
				lastErr = err.Error()
			case err == nil && lastErr != "":
				log.Infof("collecting gpu %s recovered", name)
				lastErr = ""
			}
		}
	}
}

func (c *Collector) collectUtilization(d *device) error {
	return c.collectSampledUtilization(d, nvml.GPU_UTILIZATION_SAMPLES, gpumetrics.MetricGPUUtilization,
		&d.lastUtilization, func(u nvml.Utilization) uint32 { return u.Gpu },
		func(attrs pcommon.Map) { attrs.PutStr(gpumetrics.AttrHwGPUTask, "general") })
}

func (c *Collector) collectMemoryCopyUtilization(d *device) error {
	return c.collectSampledUtilization(d, nvml.MEMORY_UTILIZATION_SAMPLES, gpumetrics.MetricMemoryCopyUtilization,
		&d.lastMemoryCopy, func(u nvml.Utilization) uint32 { return u.Memory }, nil)
}

// collectSampledUtilization reports the percentage samples NVML buffered for
// st since *lastSeen as fractions. With no new samples (typically an idle GPU)
// it reports the current utilization instead, so the series keeps reporting
// rather than going dark.
func (c *Collector) collectSampledUtilization(d *device, st nvml.SamplingType, metric string,
	lastSeen *uint64, current func(nvml.Utilization) uint32, extraAttrs func(pcommon.Map),
) error {
	type point struct {
		ts    int64
		value float64
	}
	var points []point

	valueType, samples, ret := d.d.GetSamples(st, *lastSeen)
	switch {
	case errors.Is(ret, nvml.SUCCESS):
		getValue, err := valueGetter(valueType)
		if err != nil {
			return err
		}
		newest := newestSample(samples)
		offset := nvmlOffsetNanos(time.Now(), newest)
		for _, s := range samples {
			if s.TimeStamp == 0 {
				continue
			}
			v := sampleFloat(getValue(s.SampleValue))
			if v < 0 || v > 100 {
				continue
			}
			points = append(points, point{ts: int64(s.TimeStamp)*1000 + offset, value: v / 100})
		}
		*lastSeen = max(*lastSeen, newest)
	case errors.Is(ret, nvml.ERROR_NOT_FOUND), errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		// No new samples, or no sampling on this part: fall back below.
	default:
		return fmt.Errorf("get %s samples: %s", metric, nvml.ErrorString(ret))
	}

	if len(points) == 0 {
		// *lastSeen is intentionally not advanced: it is in NVML's clock
		// domain, not wall clock, so the next GetSamples call must keep it.
		rates, ret := d.d.GetUtilizationRates()
		switch {
		case errors.Is(ret, nvml.SUCCESS):
			points = append(points, point{ts: time.Now().UnixNano(), value: float64(current(rates)) / 100})
		case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		default:
			return fmt.Errorf("get utilization rates: %s", nvml.ErrorString(ret))
		}
	}

	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		dps := b.Points(metric)
		for _, pt := range points {
			dp := dps.AppendEmpty()
			d.PutAttrs(dp.Attributes())
			if extraAttrs != nil {
				extraAttrs(dp.Attributes())
			}
			dp.SetTimestamp(pcommon.Timestamp(pt.ts))
			dp.SetDoubleValue(pt.value)
		}
	})
	return nil
}

// collectMemory reports device memory. Parts with memory shared with the CPU,
// such as GB10, don't report it.
func (c *Collector) collectMemory(d *device) error {
	const capability = "memory usage"
	if d.disabled(capability) {
		return nil
	}
	mem, ret := d.d.GetMemoryInfo()
	switch {
	case errors.Is(ret, nvml.SUCCESS):
	case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		d.disable(capability)
		return nil
	default:
		return fmt.Errorf("get memory info: %s", nvml.ErrorString(ret))
	}

	ts := pcommon.NewTimestampFromTime(time.Now())
	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		put := func(metric string) pmetric.NumberDataPoint {
			dp := b.Points(metric).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.SetTimestamp(ts)
			return dp
		}
		put(gpumetrics.MetricGPUMemoryUsage).SetIntValue(int64(mem.Used))
		put(gpumetrics.MetricGPUMemoryLimit).SetIntValue(int64(mem.Total))
		if mem.Total > 0 {
			put(gpumetrics.MetricGPUMemoryUtilization).SetDoubleValue(float64(mem.Used) / float64(mem.Total))
		}
	})
	return nil
}

// collectPowerLimit reports the power limit read at startup; it is static.
func (c *Collector) collectPowerLimit(d *device) error {
	if d.powerLimitMilliwatts == 0 {
		return nil
	}
	ts := pcommon.NewTimestampFromTime(time.Now())
	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		dp := b.Points(gpumetrics.MetricPowerLimit).AppendEmpty()
		d.PutAttrs(dp.Attributes())
		dp.SetTimestamp(ts)
		dp.SetDoubleValue(float64(d.powerLimitMilliwatts) / 1000)
	})
	return nil
}

// collectPower reports the power samples NVML buffered since d.lastPower.
// With no new samples it reports the current draw instead: some parts, such as
// GB10, never fill the sample buffer but do report the current draw.
func (c *Collector) collectPower(d *device) error {
	const capability = "power"
	if d.disabled(capability) {
		return nil
	}
	type point struct {
		ts    int64
		watts float64
	}
	var points []point

	valueType, samples, ret := d.d.GetSamples(nvml.TOTAL_POWER_SAMPLES, d.lastPower)
	switch {
	case errors.Is(ret, nvml.SUCCESS):
		getValue, err := valueGetter(valueType)
		if err != nil {
			return err
		}
		newest := newestSample(samples)
		offset := nvmlOffsetNanos(time.Now(), newest)
		for _, s := range samples {
			if s.TimeStamp == 0 {
				continue
			}
			watts := sampleFloat(getValue(s.SampleValue)) / 1000 // milliwatts to watts
			if watts < 0 || watts > 10_000 {
				continue
			}
			points = append(points, point{ts: int64(s.TimeStamp)*1000 + offset, watts: watts})
		}
		d.lastPower = max(d.lastPower, newest)
	case errors.Is(ret, nvml.ERROR_NOT_FOUND), errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		// No new samples, or no sampling on this part: fall back below.
	default:
		return fmt.Errorf("get power samples: %s", nvml.ErrorString(ret))
	}

	if len(points) == 0 {
		// d.lastPower is intentionally not advanced: it is in NVML's clock
		// domain, not wall clock, so the next GetSamples call must keep it.
		milliwatts, ret := d.d.GetPowerUsage()
		switch {
		case errors.Is(ret, nvml.SUCCESS):
			points = append(points, point{ts: time.Now().UnixNano(), watts: float64(milliwatts) / 1000})
		case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
			d.disable(capability)
			return nil
		default:
			return fmt.Errorf("get power usage: %s", nvml.ErrorString(ret))
		}
	}

	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		dps := b.Points(gpumetrics.MetricPower)
		for _, pt := range points {
			dp := dps.AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.SetTimestamp(pcommon.Timestamp(pt.ts))
			dp.SetDoubleValue(pt.watts)
		}
	})
	return nil
}

func (c *Collector) collectTemperature(d *device) error {
	const capability = "temperature"
	if d.disabled(capability) {
		return nil
	}
	temp, ret := d.d.GetTemperature(nvml.TEMPERATURE_GPU)
	switch {
	case errors.Is(ret, nvml.SUCCESS):
	case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		d.disable(capability)
		return nil
	default:
		return fmt.Errorf("get temperature: %s", nvml.ErrorString(ret))
	}

	ts := pcommon.NewTimestampFromTime(time.Now())
	c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
		dp := b.Points(gpumetrics.MetricTemperature).AppendEmpty()
		d.PutAttrs(dp.Attributes())
		dp.SetTimestamp(ts)
		dp.SetIntValue(int64(temp))
	})
	return nil
}

var clockDomains = []struct {
	name  string
	clock nvml.ClockType
}{
	{"graphics", nvml.CLOCK_GRAPHICS},
	{"sm", nvml.CLOCK_SM},
	{"memory", nvml.CLOCK_MEM},
	{"video", nvml.CLOCK_VIDEO},
}

func (c *Collector) collectClocks(d *device) error {
	for _, domain := range clockDomains {
		capability := domain.name + " clock"
		if d.disabled(capability) {
			continue
		}
		mhz, ret := d.d.GetClockInfo(domain.clock)
		switch {
		case errors.Is(ret, nvml.SUCCESS):
		case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
			// Some clock domains aren't exposed on every part; stop polling
			// the ones this device doesn't support.
			d.disable(capability)
			continue
		default:
			return fmt.Errorf("get %s clock: %s", domain.name, nvml.ErrorString(ret))
		}

		ts := pcommon.NewTimestampFromTime(time.Now())
		c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
			dp := b.Points(gpumetrics.MetricClockSpeed).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.Attributes().PutStr(gpumetrics.AttrClockDomain, domain.name)
			dp.SetTimestamp(ts)
			dp.SetIntValue(int64(mhz) * 1_000_000)
		})
	}
	return nil
}

var pcieDirections = []struct {
	name    string
	counter nvml.PcieUtilCounter
}{
	{"transmit", nvml.PCIE_UTIL_TX_BYTES},
	{"receive", nvml.PCIE_UTIL_RX_BYTES},
}

func (c *Collector) collectPCIeThroughput(d *device) error {
	for _, dir := range pcieDirections {
		capability := "pcie " + dir.name + " throughput"
		if d.disabled(capability) {
			continue
		}
		kbps, ret := d.d.GetPcieThroughput(dir.counter)
		switch {
		case errors.Is(ret, nvml.SUCCESS):
		case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
			// Unavailable where the GPU isn't behind a PCIe bus (e.g.
			// NVLink-C2C on GB10 / DGX Spark).
			d.disable(capability)
			continue
		default:
			return fmt.Errorf("get pcie %s throughput: %s", dir.name, nvml.ErrorString(ret))
		}

		ts := pcommon.NewTimestampFromTime(time.Now())
		c.rec.RecordHost(func(b *gpumetrics.MetricBuffer) {
			dp := b.Points(gpumetrics.MetricPCIeThroughput).AppendEmpty()
			d.PutAttrs(dp.Attributes())
			dp.Attributes().PutStr(gpumetrics.AttrNetworkIODirection, dir.name)
			dp.SetTimestamp(ts)
			dp.SetIntValue(int64(kbps) * 1000) // KB/s to bytes/s
		})
	}
	return nil
}

// collectProcesses reports per-process utilization. NVML returns the samples
// of every process on the device newer than the given timestamp, each tagged
// with its PID, so one call covers all of them.
func (c *Collector) collectProcesses(d *device) error {
	const capability = "process utilization"
	if d.disabled(capability) {
		return nil
	}
	samples, ret := d.d.GetProcessUtilization(d.lastProcess)
	switch {
	case errors.Is(ret, nvml.SUCCESS):
	case errors.Is(ret, nvml.ERROR_NOT_FOUND):
		// No process used the GPU since the last call.
		return nil
	case errors.Is(ret, nvml.ERROR_NOT_SUPPORTED):
		d.disable(capability)
		return nil
	default:
		return fmt.Errorf("get process utilization: %s", nvml.ErrorString(ret))
	}

	var newest uint64
	for _, s := range samples {
		newest = max(newest, s.TimeStamp)
	}
	offset := nvmlOffsetNanos(time.Now(), newest)

	for _, s := range samples {
		if s.TimeStamp == 0 || s.SmUtil > 100 || s.MemUtil > 100 {
			continue
		}
		ts := pcommon.Timestamp(int64(s.TimeStamp)*1000 + offset)
		c.rec.RecordProcess(s.Pid, func(b *gpumetrics.MetricBuffer) {
			put := func(metric string, percent uint32) {
				dp := b.Points(metric).AppendEmpty()
				d.PutIDAttrs(dp.Attributes())
				dp.SetTimestamp(ts)
				dp.SetDoubleValue(float64(percent) / 100)
			}
			put(gpumetrics.MetricProcessUtilization, s.SmUtil)
			put(gpumetrics.MetricProcessMemoryCopyUtilization, s.MemUtil)
		})
	}
	d.lastProcess = max(d.lastProcess, newest)
	return nil
}

// newestSample returns the newest timestamp among samples, 0 if none.
func newestSample(samples []nvml.Sample) uint64 {
	var newest uint64
	for _, s := range samples {
		newest = max(newest, s.TimeStamp)
	}
	return newest
}

// nvmlOffsetNanos returns the offset in nanoseconds to add to an NVML sample
// timestamp (microseconds against an unspecified reference clock, typically
// CLOCK_BOOTTIME on Linux drivers) to convert it to wall-clock nanoseconds
// since the Unix epoch. It assumes the newest sample, newest, was taken at
// about wallNow. Returns 0 if there are no usable samples.
func nvmlOffsetNanos(wallNow time.Time, newest uint64) int64 {
	if newest == 0 {
		return 0
	}
	return wallNow.UnixNano() - int64(newest)*1000
}

// sampleFloat converts a valueGetter result to float64.
func sampleFloat(v any) float64 {
	switch v := v.(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	}
	return 0
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
