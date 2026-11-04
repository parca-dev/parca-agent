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

package reporter

import (
	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// memoryPeriod is the Go runtime's heap sampling rate, which oomprof's buckets
// inherit: one sample per memorySamplePeriod bytes allocated.
var memoryPeriod = &samples.Period{Type: "space", Unit: "bytes", Value: memorySamplePeriod}

// memoryInuseProfileType matches the sample types and ContextValues layout of
// upstream's live-heap profile (open-telemetry/opentelemetry-ebpf-profiler#1747):
// ContextValues[0] is bytes in use, ContextValues[1] objects in use.
var memoryInuseProfileType = &samples.TypeMetadata{
	SampleTypes: []samples.SampleType{
		{Type: "inuse_space", Unit: "bytes", Period: memoryPeriod},
		{Type: "inuse_objects", Unit: "count", Period: memoryPeriod},
	},
	ReportValues: true,
	AppendValues: appendSpaceAndObjects,
}

// memoryAllocProfileType matches upstream's heap allocation profile
// (open-telemetry/opentelemetry-ebpf-profiler#1746): ContextValues[0] is bytes
// allocated, ContextValues[1] objects allocated.
var memoryAllocProfileType = &samples.TypeMetadata{
	SampleTypes: []samples.SampleType{
		{Type: "alloc_space", Unit: "bytes", Period: memoryPeriod},
		{Type: "alloc_objects", Unit: "count", Period: memoryPeriod},
	},
	ReportValues: true,
	AppendValues: appendSpaceAndObjects,
}

func appendSpaceAndObjects(dst []int64, meta *samples.TraceEventMeta) []int64 {
	var space, objects int64
	if len(meta.ContextValues) > 0 {
		space = int64(meta.ContextValues[0])
	}
	if len(meta.ContextValues) > 1 {
		objects = int64(meta.ContextValues[1])
	}
	return append(dst, space, objects)
}

// reportsValues reports whether a profile type describes its own values, so
// it can be emitted without a profile-type-specific branch.
func reportsValues(pt *samples.TypeMetadata) bool {
	return pt != nil && pt.ReportValues && pt.AppendValues != nil && len(pt.SampleTypes) > 0
}

func sampleTypeOf(t samples.SampleType) sampleType {
	st := sampleType{Type: t.Type, Unit: t.Unit}
	if t.Period != nil {
		st.PeriodType, st.PeriodUnit, st.Period = t.Period.Type, t.Period.Unit, t.Period.Value
	}
	return st
}

// addTypedSamples adds one sample per sample type meta.ProfileType declares,
// valued by its AppendValues, and returns how many it added. A zero value adds
// nothing to a profile, so it is not emitted. meta.ProfileType must satisfy
// reportsValues.
func (b *pprofileBuilder) addTypedSamples(res resourceLabels, s sampleData,
	meta *samples.TraceEventMeta,
) int {
	pt := meta.ProfileType
	var scratch [4]int64
	values := pt.AppendValues(scratch[:0], meta)

	added := 0
	for i, t := range pt.SampleTypes {
		if i >= len(values) {
			break
		}
		if values[i] == 0 {
			continue
		}
		s.Value = values[i]
		b.AddSample(res, sampleTypeOf(t), s)
		added++
	}
	return added
}

// addMemorySamples adds a batch of oomprof samples from one process: the
// in-use profile always, and the allocation profile when reportAllocs is set.
func (b *pprofileBuilder) addMemorySamples(res resourceLabels, sampleLabels labels.Labels,
	memSamples []oomprof.Sample, meta oomprof.SampleMeta, reportAllocs bool,
) {
	var customLabels map[libpf.String]libpf.String
	if len(meta.CustomLabels) > 0 {
		customLabels = make(map[libpf.String]libpf.String, len(meta.CustomLabels))
		for k, v := range meta.CustomLabels {
			customLabels[libpf.Intern(k)] = libpf.Intern(v)
		}
	}

	var contextValues [2]uint64
	event := &samples.TraceEventMeta{ContextValues: contextValues[:]}

	for i := range memSamples {
		ms := &memSamples[i]

		t := &libpf.Trace{CustomLabels: customLabels}
		for _, addr := range ms.Addresses {
			t.Frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: libpf.AddressOrLineno(addr),
			})
		}

		s := sampleData{
			Frames:       t.Frames,
			TraceHash:    hashTrace(t),
			Timestamp:    meta.Timestamp,
			SampleLabels: sampleLabels,
			CustomLabels: customLabels,
			// The build ID and executable path travel beside the frames
			// rather than on them, so the converter does not mistake them
			// for a resolved function name and file.
			SyntheticMemoryFrames: true,
			MemoryBuildID:         meta.BuildID,
			MemoryExecPath:        meta.ExecutablePath,
			Snapshot:              true,
		}

		event.ProfileType = memoryInuseProfileType
		contextValues[0], contextValues[1] = ms.AllocBytes-ms.FreeBytes, ms.Allocs-ms.Frees
		b.addTypedSamples(res, s, event)

		if reportAllocs {
			event.ProfileType = memoryAllocProfileType
			contextValues[0], contextValues[1] = ms.AllocBytes, ms.Allocs
			b.addTypedSamples(res, s, event)
		}
	}
}
