// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Copied from ebpf-profiler's traceutil tests. The expected hashes pin
// hashTrace to the upstream calculation, so traces keep the hashes they had.

func newTrace() *libpf.Trace {
	trace := &libpf.Trace{}
	trace.Frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0,
		Mapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID: libpf.NewFileID(0, 0),
			}),
		}),
	})
	trace.Frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 1,
		Mapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID: libpf.NewFileID(1, 1),
			}),
		}),
	})
	trace.Frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 2,
		Mapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID: libpf.NewFileID(2, 2),
			}),
		}),
	})
	return trace
}

func TestHashTrace(t *testing.T) {
	tests := map[string]struct {
		trace  *libpf.Trace
		result libpf.TraceHash
	}{
		"empty trace": {
			trace:  &libpf.Trace{},
			result: libpf.NewTraceHash(0x6c62272e07bb0142, 0x62b821756295c58d)},
		"native trace": {
			trace:  newTrace(),
			result: libpf.NewTraceHash(0x21c6fe4c62868856, 0xcf510596eab68dc8)},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, hashTrace(testcase.trace))
		})
	}
}
