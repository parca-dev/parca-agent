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

// This file is the inverse of the v2 write path. appendLocationV2 turns a
// libpf.Frame into location columns; the entry points here write those columns
// directly, which is what an importer needs -- reading a padata file back, or
// converting from another encoding -- because there is no libpf.Frame to
// classify in either case.

package reporter

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// LocationV2 is a decoded stack frame in neutral terms: exactly what the v2
// location columns hold, with none of the machinery that produced it.
type LocationV2 struct {
	Address   uint64
	FrameType string

	// The Has fields distinguish an absent column value from an empty one.
	// The v2 schema makes both nullable and the arrow writers append null
	// rather than "", so the round trip has to preserve that difference.
	MappingFile    string
	HasMappingFile bool
	MappingBuildID string
	HasMappingID   bool

	Lines []LineV2
}

// LineV2 is one line entry within a LocationV2.
type LineV2 struct {
	Line     uint64
	Column   uint64
	Function FunctionV2
}

// AppendLocation writes one location into the builders and returns its
// dictionary index. Callers own deduplication: pass the same location twice and
// it occupies two dictionary entries.
func (b *StacktraceDictBuilderV2) AppendLocation(loc LocationV2) uint32 {
	idx := uint32(b.lineListOffsets.Len())

	b.lineListOffsets.Append(int32(b.lineNumber.Len()))
	b.locAddress.Append(loc.Address)

	if loc.FrameType != "" {
		b.locFrameType.AppendString(loc.FrameType)
	} else {
		b.locFrameType.AppendNull()
	}
	if loc.HasMappingFile {
		b.locMappingFile.AppendString(loc.MappingFile)
	} else {
		b.locMappingFile.AppendNull()
	}
	if loc.HasMappingID {
		b.locMappingID.AppendString(loc.MappingBuildID)
	} else {
		b.locMappingID.AppendNull()
	}

	for _, l := range loc.Lines {
		b.lineNumber.Append(l.Line)
		b.lineColumn.Append(l.Column)
		b.funcIndices.Append(b.funcDict.AppendFunction(l.Function))
	}

	return idx
}

// AppendStacktraceIndices appends a stacktrace from location indices that
// AppendLocation already returned, reusing ListView dimensions for a repeated
// traceHash exactly as AppendStacktrace does.
func (b *StacktraceDictBuilderV2) AppendStacktraceIndices(traceHash libpf.TraceHash, indices []uint32) {
	if entry, ok := b.index[traceHash]; ok {
		b.offsets.Append(int32(entry.offset))
		b.sizes.Append(int32(entry.listSize))
		b.length++
		return
	}

	startOffset := b.indices.Len()
	for _, idx := range indices {
		b.indices.Append(idx)
	}

	b.index[traceHash] = listEntryRef{offset: startOffset, listSize: len(indices)}
	b.offsets.Append(int32(startOffset))
	b.sizes.Append(int32(len(indices)))
	b.length++
}
