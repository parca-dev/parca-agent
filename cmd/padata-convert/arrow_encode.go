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

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/google/uuid"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter"
)

// encodeArrowV2 writes canonical samples back into a v2 sample record, using
// the same SampleWriterV2 the agent writes with. Going through the production
// writer rather than hand-rolling the arrow buffers is deliberate: it is the
// only way the round trip proves anything about the format the agent actually
// emits.
func encodeArrowV2(samples []canonSample, mem memory.Allocator) (arrow.Record, error) {
	w := reporter.NewSampleWriterV2(mem)

	// Locations dedupe on their canonical key, mirroring what
	// appendLocationV2 does with libpf.Frame identity.
	locIndex := map[string]uint32{}

	for i := range samples {
		s := &samples[i]

		for name, value := range s.Labels {
			w.Label(name).AppendString(value)
		}

		indices := make([]uint32, 0, len(s.Stack))
		for _, loc := range s.Stack {
			key := locationKeyOf(loc)
			idx, ok := locIndex[key]
			if !ok {
				idx = w.Stacktrace.AppendLocation(toLocationV2(loc))
				locIndex[key] = idx
			}
			indices = append(indices, idx)
		}

		hash, err := traceHashFromHex(s.StacktraceID)
		if err != nil {
			return nil, fmt.Errorf("sample %d: %w", i, err)
		}
		w.Stacktrace.AppendStacktraceIndices(hash, indices)

		var idBytes [16]byte
		hash.PutBytes16(&idBytes)
		w.StacktraceID.Append(uuid.UUID(idBytes))

		w.Value.Append(s.Value)
		w.Timestamp.Append(arrow.Timestamp(s.Timestamp))
		w.Period.Append(s.Period)
		w.Duration.Append(s.Duration)
		w.Producer.AppendString(s.Producer)
		w.SampleType.AppendString(s.SampleType)
		w.SampleUnit.AppendString(s.SampleUnit)
		w.PeriodType.AppendString(s.PeriodType)
		w.PeriodUnit.AppendString(s.PeriodUnit)
		if s.Temporality != "" {
			w.Temporality.AppendString(s.Temporality)
		} else {
			w.Temporality.AppendNull()
		}
	}

	return w.NewRecord(), nil
}

func toLocationV2(loc canonLocation) reporter.LocationV2 {
	out := reporter.LocationV2{
		Address:   loc.Address,
		FrameType: loc.FrameType,
		// The canonical form cannot distinguish a null mapping column from an
		// empty string, so non-empty means present. That is safe because the
		// writers never emit an empty-string mapping.
		MappingFile:    loc.MappingFile,
		HasMappingFile: loc.MappingFile != "",
		MappingBuildID: loc.MappingBuildID,
		HasMappingID:   loc.MappingBuildID != "",
	}
	for _, l := range loc.Lines {
		out.Lines = append(out.Lines, reporter.LineV2{
			Line:   l.Line,
			Column: l.Column,
			Function: reporter.FunctionV2{
				SystemName: l.SystemName,
				Filename:   l.Filename,
				StartLine:  l.StartLine,
			},
		})
	}
	return out
}

// traceHashFromHex rebuilds the 16-byte trace hash the stacktrace_id column
// carries. It is the ListView dedup key, so a wrong value would silently change
// how stacks are shared.
func traceHashFromHex(s string) (libpf.TraceHash, error) {
	if s == "" {
		return libpf.TraceHash{}, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return libpf.TraceHash{}, fmt.Errorf("decode stacktrace_id: %w", err)
	}
	if len(b) != 16 {
		return libpf.TraceHash{}, fmt.Errorf("stacktrace_id is %d bytes, want 16", len(b))
	}
	return libpf.TraceHashFromBytes(b)
}
