// Copyright 2024 The Parca Authors
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
//

package bpfmaps

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

func TestTakeChunk(t *testing.T) {
	const Max int = 5
	inner := func(ut unwind.CompactUnwindTable, fdes frame.FrameDescriptionEntries, expectedChunkOffsets []int) {
		totalLen := 0
		i := 0
		remaining := Max
		origLen := len(ut)
		for len(ut) > 0 {
			var chunk unwind.CompactUnwindTable
			chunk, ut = takeChunk(ut, fdes, uint64(remaining))
			if len(chunk) == 0 {
				require.NotEqual(t, Max, remaining)
				require.Equal(t, expectedChunkOffsets[i], totalLen)
				i++
				remaining = Max
				continue
			}
			require.LessOrEqual(t, len(chunk), remaining)
			remaining -= len(chunk)
			totalLen += len(chunk)
		}
		require.Equal(t, expectedChunkOffsets[i], origLen)
		require.Equal(t, len(expectedChunkOffsets)-1, i)
	}
	// two functions that fit in the same chunk
	inner([]unwind.CompactUnwindTableRow{
		unwind.NewCompactUnwindTableRow(0, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(4, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(17, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(22, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(36, 0, 0, 0, 0, 0),
	}, []*frame.FrameDescriptionEntry{
		frame.NewFrameDescriptionEntry(0, nil, nil, 0, 18, binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 18, (37 - 18), binary.LittleEndian),
	}, []int{5})

	// two functions that barely don't fit in the same chunk
	inner([]unwind.CompactUnwindTableRow{
		unwind.NewCompactUnwindTableRow(0, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(4, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(17, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(22, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(36, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(39, 0, 0, 0, 0, 0),
	}, []*frame.FrameDescriptionEntry{
		frame.NewFrameDescriptionEntry(0, nil, nil, 0, 18, binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 18, (40 - 18), binary.LittleEndian),
	}, []int{3, 6})

	// the first two fit, but the third doesn't
	inner([]unwind.CompactUnwindTableRow{
		unwind.NewCompactUnwindTableRow(0, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(4, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(17, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(22, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(36, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(39, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(42, 0, 0, 0, 0, 0),
	}, []*frame.FrameDescriptionEntry{
		frame.NewFrameDescriptionEntry(0, nil, nil, 0, 18, binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 18, (23 - 18), binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 23, (43 - 23), binary.LittleEndian),
	}, []int{4, 7})

	// two functions that fit in the same chunk,
	// bounded by an end marker
	inner([]unwind.CompactUnwindTableRow{
		unwind.NewCompactUnwindTableRow(0, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(4, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(17, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(22, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(36, 0, 4, 0, 0, 0),
	}, []*frame.FrameDescriptionEntry{
		frame.NewFrameDescriptionEntry(0, nil, nil, 0, 18, binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 18, (36 - 18), binary.LittleEndian),
	}, []int{5})

	// two functions that don't fit in the same chunk,
	// both bounded by end markers
	inner([]unwind.CompactUnwindTableRow{
		unwind.NewCompactUnwindTableRow(0, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(4, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(17, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(22, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(36, 0, 4, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(39, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(40, 0, 4, 0, 0, 0),
	}, []*frame.FrameDescriptionEntry{
		frame.NewFrameDescriptionEntry(0, nil, nil, 0, 36, binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 39, (40 - 39), binary.LittleEndian),
	}, []int{5, 7})

	// two functions that don't fit, because only the end marker of the
	// second overruns, by one instruction
	inner([]unwind.CompactUnwindTableRow{
		unwind.NewCompactUnwindTableRow(0, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(4, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(17, 0, 4, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(22, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(38, 0, 0, 0, 0, 0),
		unwind.NewCompactUnwindTableRow(39, 0, 4, 0, 0, 0),
	}, []*frame.FrameDescriptionEntry{
		frame.NewFrameDescriptionEntry(0, nil, nil, 0, 17, binary.LittleEndian),
		frame.NewFrameDescriptionEntry(0, nil, nil, 22, (39 - 22), binary.LittleEndian),
	}, []int{3, 6})
}
