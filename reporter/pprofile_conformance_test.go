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
	"testing"
	"time"

	"github.com/open-telemetry/sig-profiling/profcheck"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	v1profiles "go.opentelemetry.io/proto/otlp/profiles/v1development"
	"google.golang.org/protobuf/proto"
)

// requireConformant runs the OTLP profiles conformance checker over a built
// batch, going through the proto wire form so the test sees what a collector
// would receive rather than the in-memory pdata view.
func requireConformant(t *testing.T, profiles pprofile.Profiles) {
	t.Helper()

	contents, err := pprofileotlp.NewExportRequestFromProfiles(profiles).MarshalProto()
	require.NoError(t, err)

	var data v1profiles.ProfilesData
	require.NoError(t, proto.Unmarshal(contents, &data))

	require.NoError(t, profcheck.ConformanceChecker{
		CheckDictionaryDuplicates: true,
		CheckSampleTimestampShape: true,
	}.Check(&data))
}

// TestPprofileConformance pins that what the OTLP exporter puts on the wire
// satisfies the profiles spec. It is a spec check, not a shape check: the
// dictionary rules it enforces (every table reserving index 0 for a zero
// value) are invisible in the pdata API and were all being violated before,
// which no other test in this package noticed.
func TestPprofileConformance(t *testing.T) {
	b := testBuilder(t)

	// Two processes, two sample types, a shared stack and a symbolized frame,
	// so the mapping, function, location, stack, attribute and string tables
	// are all populated rather than trivially empty.
	native := frame(t, libpf.Frame{Type: libpf.NativeFrame})
	res := resourceLabels{
		Labels:      labels.FromStrings("node", "test-node"),
		PID:         1000,
		ServiceName: "svc-a",
	}
	other := resourceLabels{
		Labels: labels.FromStrings("node", "test-node"),
		PID:    2000,
	}

	now := time.Unix(1000, 0)
	b.AddSample(res, cpuSampleType(19), sampleData{
		Frames:       native,
		Value:        1,
		Timestamp:    uint64(now.UnixNano()),
		SampleLabels: labels.FromStrings("thread_name", "worker", "cpu", "3"),
	})
	b.AddSample(res, offCPUSampleType, sampleData{
		Frames: native, Value: 500, Timestamp: uint64(now.Add(time.Second).UnixNano()),
	})
	b.AddSample(other, cpuSampleType(19), sampleData{
		Frames: native, Value: 1, Timestamp: uint64(now.Add(2 * time.Second).UnixNano()),
	})

	requireConformant(t, b.Build(now, now.Add(5*time.Second)))
}

// TestPprofileDictionarySentinels pins the reserved index 0 in every table.
//
// Deliberately not a requireConformant call: a batch with no samples has no
// resource_profiles, which the checker rejects on its own terms, and the
// exporter never ships one anyway (SampleCount gates that). What matters here
// is that reset leaves the sentinels in place for the *next* batch, since
// every index the builder hands out afterwards is relative to them.
func TestPprofileDictionarySentinels(t *testing.T) {
	b := testBuilder(t)
	dict := b.Build(time.Unix(0, 0), time.Unix(5, 0)).Dictionary()

	require.Equal(t, 1, dict.MappingTable().Len(), "mapping_table[0] reserved")
	require.Equal(t, 1, dict.LocationTable().Len(), "location_table[0] reserved")
	require.Equal(t, 1, dict.FunctionTable().Len(), "function_table[0] reserved")
	require.Equal(t, 1, dict.StackTable().Len(), "stack_table[0] reserved")
	require.Equal(t, 1, dict.AttributeTable().Len(), "attribute_table[0] reserved")
	require.Equal(t, 1, dict.LinkTable().Len(), "link_table[0] reserved")
	require.Equal(t, 1, dict.StringTable().Len(), "string_table[0] is the empty string")
	require.Empty(t, dict.StringTable().At(0))

	// The sentinels are zero values, not merely present.
	require.Zero(t, dict.LocationTable().At(0).Address())
	require.Zero(t, dict.LocationTable().At(0).Lines().Len())
	require.Zero(t, dict.StackTable().At(0).LocationIndices().Len())
	require.Zero(t, dict.AttributeTable().At(0).KeyStrindex())
	require.Zero(t, dict.AttributeTable().At(0).UnitStrindex())
}

// TestPprofileConformanceSampleOutsideWindow pins the timestamp widening.
// Samples are stamped when the kernel took them, so one can predate the flush
// window the exporter passes to Build; OTLP requires every timestamp to fall
// inside the profile's own window, so Build has to stretch it rather than emit
// a sample outside its profile.
func TestPprofileConformanceSampleOutsideWindow(t *testing.T) {
	b := testBuilder(t)
	start := time.Unix(1000, 0)
	end := start.Add(5 * time.Second)

	// One sample before the window opens, one on the exclusive end boundary.
	b.AddSample(resourceLabels{PID: 1}, cpuSampleType(19), sampleData{
		Frames:    frame(t, libpf.Frame{Type: libpf.NativeFrame}),
		Value:     1,
		Timestamp: uint64(start.Add(-time.Second).UnixNano()),
	})
	b.AddSample(resourceLabels{PID: 1}, cpuSampleType(19), sampleData{
		Frames:    frame(t, libpf.Frame{Type: libpf.NativeFrame}),
		Value:     1,
		Timestamp: uint64(end.UnixNano()),
	})

	out := b.Build(start, end)
	requireConformant(t, out)

	p := out.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles().At(0)
	require.LessOrEqual(t, uint64(p.Time()), uint64(start.Add(-time.Second).UnixNano()),
		"window must open no later than the earliest sample")
	require.Greater(t, uint64(p.Time())+p.DurationNano(), uint64(end.UnixNano()),
		"window must close after the latest sample, the end being exclusive")
}
