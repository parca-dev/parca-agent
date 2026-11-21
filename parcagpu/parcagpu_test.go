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

package parcagpu

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// recordingReporter keeps what it is handed, reading the value while the
// context values are valid, as the real reporters do.
type recordingReporter struct {
	traces []*libpf.Trace
	values []int64
}

func (r *recordingReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta,
) error {
	r.traces = append(r.traces, trace)
	r.values = append(r.values, meta.ProfileType.AppendValues(nil, meta)...)
	return nil
}

// TestWrapLabelsBlockingCalls checks that a cuda_blocking_call trace goes
// straight through, weighted by its blocked time and labeled with the call,
// and that other traces are untouched.
func TestWrapLabelsBlockingCalls(t *testing.T) {
	inner := &recordingReporter{}
	rep := Wrap(inner, nil)

	trace := &libpf.Trace{}
	trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x10})
	var cbid int32 = -126 // cuStreamSynchronize: driver API cbids are negative
	require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
		ProfileType: gpu.ProfileTypeCudaBlocking,
		// weight, duration, cbid | device<<32
		ContextValues: []uint64{10_000, 3_000,
			uint64(uint32(cbid)) | 2<<32},
	}))

	cpu := &libpf.Trace{}
	require.NoError(t, rep.ReportTraceEvent(cpu, &samples.TraceEventMeta{
		ProfileType: &samples.TypeMetadata{
			SampleTypes:  []samples.SampleType{{Type: "samples", Unit: "count"}},
			AppendValues: samples.AppendFirstContextValue,
		},
	}))

	require.Len(t, inner.traces, 2)
	require.Equal(t, []int64{10_000, 0}, inner.values)
	require.Equal(t, map[libpf.String]libpf.String{
		libpf.Intern("cuda_api"):    libpf.Intern("cuStreamSynchronize"),
		libpf.Intern("cuda_device"): libpf.Intern("2"),
	}, inner.traces[0].CustomLabels)
	require.Equal(t, trace.Frames, inner.traces[0].Frames, "the CPU stack is the stack")
	require.Nil(t, inner.traces[1].CustomLabels)
}
