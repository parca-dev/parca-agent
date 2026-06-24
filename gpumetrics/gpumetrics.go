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
// standalone gpu-metrics-agent NVML producer, adapted to run inside parca-agent
// as a metricexport.Producer.
//
// The NVML producer (nvidia.go) requires cgo and a dynamically linked binary
// so go-nvml can dlopen libnvidia-ml at runtime; it is excluded by the "nonvml"
// build tag, under which nvidia_stub.go provides a no-op stand-in for the
// fully-static build. This file holds the declarations shared by both builds.
package gpumetrics

// ScopeName is the OTLP instrumentation scope GPU metrics are reported under.
const ScopeName = "parca.nvidia_gpu_metrics"

// LabelResolver resolves additional attributes (e.g. Kubernetes namespace,
// pod, container) for a process by its host PID. The returned labels are
// attached to per-process GPU metric data points so they share identity with
// parca-agent's profiles. NVML reports host PIDs, so the resolver must also
// operate in the host PID namespace (the standard parca-agent deployment).
type LabelResolver interface {
	LabelsForPID(pid uint32) map[string]string
}
