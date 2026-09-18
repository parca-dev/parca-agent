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

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Stand-ins for the profile types the profiler registers for its own three
// kinds. Upstream declares those as anonymous literals we cannot reach (see
// profiletypes.go), so tests rebuild them field for field.
var (
	testProfileTypeSampling = &samples.TypeMetadata{
		PeriodType: "cpu",
		PeriodUnit: "nanoseconds",
		SampleType: sampleTypeSampling,
		SampleUnit: "count",
	}
	testProfileTypeOffCPU = &samples.TypeMetadata{
		SampleType:   sampleTypeOffCPU,
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
	testProfileTypeProbe = &samples.TypeMetadata{
		SampleType: sampleTypeProbe,
		SampleUnit: "count",
	}
)

// TestGPUSampleTypeConstantsMatchProfiler pins our two GPU constants to the
// metadata the profiler actually registers. interpreter/gpu is the one place
// that exports its profile types, so these are the only two we can check
// against the real thing rather than against a copy; if a rename there ever
// lands, GPU samples would otherwise start falling through to the default
// case and be dropped with only a log line.
func TestGPUSampleTypeConstantsMatchProfiler(t *testing.T) {
	require.Equal(t, sampleTypeCUDA, gpu.ProfileTypeCuda.SampleType)
	require.Equal(t, sampleTypeGpuPC, gpu.ProfileTypeGpuPC.SampleType)
}

func TestProfileTypeNameHandlesNil(t *testing.T) {
	require.Empty(t, profileTypeName(nil), "memory traces carry no profile type")
	require.Equal(t, sampleTypeProbe, profileTypeName(testProfileTypeProbe))
}
