// Copyright 2022-2024 The Parca Authors
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

package profiler

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEfficientBufferInvariants(t *testing.T) {
	buf := make(EfficientBuffer, 0, 1000)
	subSlice := buf.Slice(10)
	require.Len(t, buf, 10)
	require.Equal(t, 1000, cap(buf))

	require.Len(t, subSlice, 10)
	require.Equal(t, 1000, cap(subSlice))
}

func TestEfficientBufferInvariants2(t *testing.T) {
	buf := make(EfficientBuffer, 0, 1000)
	subSlice := buf.Slice(10)
	subSlice.PutUint8(1)

	require.Len(t, buf, 10)
	require.Equal(t, 1000, cap(buf))

	require.Len(t, subSlice, 9)
	require.Equal(t, 999, cap(subSlice))
}

func TestEfficientBufferInvariant3(t *testing.T) {
	buf := make(EfficientBuffer, 0, 1000)
	subSlice := buf.Slice(10)
	subSlice.PutUint8(1)
	subSlice.PutUint8(1)

	require.Len(t, buf, 10)
	require.Equal(t, 1000, cap(buf))

	require.Len(t, subSlice, 8)
	require.Equal(t, 998, cap(subSlice))
}

func TestEfficientBufferAgainstBinaryWrite(t *testing.T) {
	buf := make(EfficientBuffer, 0, 1000)
	subSlice := buf.Slice(1000)
	subSlice.PutUint8(111)
	subSlice.PutUint16(222)
	subSlice.PutUint32(333)
	subSlice.PutUint64(444)

	buf2 := bytes.NewBuffer(make([]byte, 0, 1000))
	binary.Write(buf2, binary.LittleEndian, uint8(111))
	binary.Write(buf2, binary.LittleEndian, uint16(222))
	binary.Write(buf2, binary.LittleEndian, uint32(333))
	binary.Write(buf2, binary.LittleEndian, uint64(444))

	require.Equal(t, buf2.Bytes()[:15], []byte(buf[:15]))
}

func BenchmarkEfficientBufferSliceWrite(b *testing.B) {
	b.ReportAllocs()

	buf := make(EfficientBuffer, 0, b.N*8)
	subSlice := buf.Slice(b.N * 8)
	number := uint64(111)
	for n := 0; n < b.N; n++ {
		subSlice.PutUint64(number)
	}
}

func BenchmarkBinaryWrite(b *testing.B) {
	b.ReportAllocs()

	buf := bytes.NewBuffer(make([]byte, 0, b.N*8))
	number := uint64(111)
	for n := 0; n < b.N; n++ {
		binary.Write(buf, binary.LittleEndian, number)
	}
}
