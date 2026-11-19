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

// Package gpumetrics collects NVIDIA GPU metrics via NVML and renders them as
// OTLP metrics for the metricexport egress path. It is a port of Polar Signals'
// standalone gpu-metrics-agent NVML producer, adapted to the
// metricexport.Producer interface.
//
// Metrics follow the OTel hardware semantic conventions (hw.*) where those
// model what NVML reports, and use the nvidia.* namespace where they don't.
// Device metrics sit on the host's resource; per-process metrics sit on one
// resource per process, built by the same code as the process's profiles so
// both carry the same identity.
//
// The NVML collectors (subpackage nvidia) require cgo and a dynamically linked
// binary so go-nvml can dlopen libnvidia-ml at runtime, so parca-agent only
// links them when built with the gpumetrics build tag. This package is pure Go.
package gpumetrics

import (
	"os"
	"path/filepath"
)

// ScopeName is the OTLP instrumentation scope GPU metrics are reported under.
const ScopeName = "parca.nvidia_gpu_metrics"

// Metric names. hw.* follow the OTel hardware semantic conventions; nvidia.*
// cover what NVML reports that those conventions don't model.
const (
	MetricGPUUtilization       = "hw.gpu.utilization"
	MetricGPUMemoryUsage       = "hw.gpu.memory.usage"
	MetricGPUMemoryLimit       = "hw.gpu.memory.limit"
	MetricGPUMemoryUtilization = "hw.gpu.memory.utilization"
	MetricPower                = "hw.power"
	MetricEnergy               = "hw.energy"
	MetricTemperature          = "hw.temperature"

	MetricMemoryCopyUtilization        = "nvidia.gpu.memory_copy.utilization"
	MetricPowerLimit                   = "nvidia.gpu.power.limit"
	MetricClockSpeed                   = "nvidia.gpu.clock.speed"
	MetricClockEvent                   = "nvidia.gpu.clock.event"
	MetricPCIeThroughput               = "nvidia.gpu.pcie.throughput"
	MetricNVLinkThroughput             = "nvidia.gpu.nvlink.throughput"
	MetricC2CThroughput                = "nvidia.gpu.c2c.throughput"
	MetricSMUtilization                = "nvidia.gpu.sm.utilization"
	MetricSMOccupancy                  = "nvidia.gpu.sm.occupancy"
	MetricPipeUtilization              = "nvidia.gpu.pipe.utilization"
	MetricDRAMBandwidthUtilization     = "nvidia.gpu.dram.bandwidth.utilization"
	MetricProcessUtilization           = "nvidia.gpu.process.utilization"
	MetricProcessMemoryCopyUtilization = "nvidia.gpu.process.memory_copy.utilization"
	MetricProcessMemoryUsage           = "nvidia.gpu.process.memory.usage"
)

// Attribute keys. The hw.* and network.* keys are semconv's.
const (
	attrHwID               = "hw.id"
	attrHwName             = "hw.name"
	attrHwType             = "hw.type"
	attrHwVendor           = "hw.vendor"
	attrHwModel            = "hw.model"
	attrHwDriverVersion    = "hw.driver_version"
	AttrHwGPUTask          = "hw.gpu.task"
	AttrNetworkIODirection = "network.io.direction"
	AttrClockDomain        = "nvidia.gpu.clock.domain"
	AttrClockEventReason   = "nvidia.gpu.clock.event.reason"
	AttrPipe               = "nvidia.gpu.pipe"
)

// metricSpec describes how a metric is rendered. Gauges unless sum is set, in
// which case it is a cumulative sum: semconv's Counter if monotonic is set,
// its UpDownCounter otherwise.
type metricSpec struct {
	unit        string
	description string
	sum         bool
	monotonic   bool
}

var metricSpecs = map[string]metricSpec{
	MetricGPUUtilization:       {unit: "1", description: "Fraction of time spent in a specific task."},
	MetricGPUMemoryUsage:       {unit: "By", description: "GPU memory used.", sum: true},
	MetricGPUMemoryLimit:       {unit: "By", description: "Size of the GPU memory.", sum: true},
	MetricGPUMemoryUtilization: {unit: "1", description: "Fraction of GPU memory used."},
	MetricPower:                {unit: "W", description: "Instantaneous power consumed by the component."},
	MetricEnergy:               {unit: "J", description: "Energy consumed by the component.", sum: true, monotonic: true},
	MetricTemperature:          {unit: "Cel", description: "Temperature in degrees Celsius."},

	MetricMemoryCopyUtilization: {unit: "1", description: "Fraction of time device memory was being read or written."},
	MetricPowerLimit:            {unit: "W", description: "Power limit the driver currently enforces on the GPU."},
	MetricClockSpeed:            {unit: "Hz", description: "Current clock speed of a GPU clock domain."},
	MetricClockEvent: {
		unit:        "1",
		description: "1 while the reason is holding the GPU's clocks down, else 0. Its mean is the fraction of time it was active.",
	},
	MetricPCIeThroughput:   {unit: "By/s", description: "PCIe throughput of the GPU."},
	MetricNVLinkThroughput: {unit: "By/s", description: "NVLink throughput of the GPU, over all links."},
	MetricC2CThroughput:    {unit: "By/s", description: "Data throughput over the GPU's chip-to-chip (NVLink-C2C) link to the CPU."},
	MetricSMUtilization:    {unit: "1", description: "Fraction of the GPU's streaming multiprocessors that were busy."},
	MetricSMOccupancy: {
		unit:        "1",
		description: "Fraction of the theoretical maximum of warps that were resident on the streaming multiprocessors.",
	},
	MetricPipeUtilization: {
		unit: "1",
		description: "Fraction of time the streaming multiprocessors used an execution pipe. " +
			"tensor counts any tensor operation and includes the tensor_* pipes; fp* count non-tensor math.",
	},
	MetricDRAMBandwidthUtilization: {unit: "1", description: "Fraction of the theoretical maximum DRAM bandwidth used."},
	MetricProcessUtilization: {
		unit:        "1",
		description: "Fraction of time the process ran kernels on the GPU's streaming multiprocessors.",
	},
	MetricProcessMemoryCopyUtilization: {
		unit:        "1",
		description: "Fraction of time device memory was being read or written on behalf of the process.",
	},
	MetricProcessMemoryUsage: {unit: "By", description: "GPU memory used by the process.", sum: true},
}

// CountNVIDIAGPUs counts the GPUs the NVIDIA kernel driver has bound, one
// directory per GPU under <procRoot>/driver/nvidia/gpus. This needs neither
// NVML nor /dev/nvidia* in the container, only a loaded driver, which NVML
// requires anyway.
func CountNVIDIAGPUs(procRoot string) int {
	entries, err := os.ReadDir(filepath.Join(procRoot, "driver", "nvidia", "gpus"))
	if err != nil {
		return 0
	}
	return len(entries)
}
