// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"hash/fnv"
	"strconv"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// hashTrace calculates the hash of a trace and returns it.
// Be aware that changes to this calculation will break the ability to
// look backwards for the same TraceHash in our backend.
//
// Copied verbatim from ebpf-profiler's traceutil.HashTrace, which upstream
// deleted along with profiler-side trace hashing.
func hashTrace(trace *libpf.Trace) libpf.TraceHash {
	var buf [24]byte
	h := fnv.New128a()
	for _, uniqueFrame := range trace.Frames {
		frame := uniqueFrame.Value()
		_, _ = h.Write(frame.FileID.Bytes())
		// Using FormatUint() or putting AppendUint() into a function leads
		// to escaping to heap (allocation).
		_, _ = h.Write(strconv.AppendUint(buf[:0], uint64(frame.AddressOrLineno), 10))
	}
	// make instead of nil avoids a heap allocation
	traceHash, _ := libpf.TraceHashFromBytes(h.Sum(make([]byte, 0, 16)))
	return traceHash
}
