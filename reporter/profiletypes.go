// Copyright 2025 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reporter

import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

// The profiler tells us what kind of sample we got via *samples.TypeMetadata.
// It registers one of those per kind at load time and hands the same pointer
// back on every event, so identity comparison would be the obvious way to tell
// them apart -- but the pointers are not reachable from here. Upstream
// declares them as anonymous literals at each registration site
// (tracer/systemconfig.go for sampling, probes/offcpu and probes/uprobe for
// the rest) and the origin registry keeps them private, exposing only the
// uint16 ID. That is deliberate: upstream's own converter never asks which
// kind a sample is, it just copies the metadata's fields into the profile.
//
// So we match on SampleType, which is unique across every kind we handle and
// stable across the probe restructure that moved off-CPU and probes out of
// the tracer. Nothing in either repo assigns to a TypeMetadata field after
// construction, so the string we read is the one the profiler registered.
// (--merge-gpu-profiles does relabel GPU samples, but it rewrites the profile
// we emit, not the metadata we were handed.)
//
// The cost of this approach is that an upstream rename lands as samples
// silently falling through to the default case, so each switch logs there.
const (
	sampleTypeSampling = "samples"
	sampleTypeOffCPU   = "off_cpu"
	sampleTypeProbe    = "events"
	sampleTypeCUDA     = "gpu_kernel_time"
	sampleTypeGpuPC    = "gpu_pcsample"
)

// profileTypeName returns the SampleType of the profile type a sample carries,
// or "" when the profiler did not attach one (memory traces, which never go
// through the profile-type switches).
func profileTypeName(pt *samples.TypeMetadata) string {
	if pt == nil {
		return ""
	}
	return pt.SampleType
}
