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

import "encoding/binary"

type EfficientBuffer []byte

// Slice returns a slice re-sliced from the original EfficientBuffer.
// This is useful to efficiently write byte by byte, for example, when
// setting BPF maps without incurring in extra allocations in the writing
// methods, or changing the capacity of the underlying memory buffer.
//
// Callers are responsible to ensure that there is enough capacity left
// for the passed size.
func (eb *EfficientBuffer) Slice(size int) EfficientBuffer {
	newSize := len(*eb) + size
	subSlice := (*eb)[len(*eb):newSize]
	// Extend its length.
	*eb = (*eb)[:newSize]
	return subSlice
}

// PutUint64 writes the passed uint64 in little
// endian and advances the current slice.
func (eb *EfficientBuffer) PutUint64(v uint64) {
	binary.LittleEndian.PutUint64((*eb)[:8], v)
	*eb = (*eb)[8:]
}

// PutUint32 writes the passed uint32 in little
// endian and advances the current slice.
func (eb *EfficientBuffer) PutUint32(v uint32) {
	binary.LittleEndian.PutUint32((*eb)[:4], v)
	*eb = (*eb)[4:]
}

// PutUint16 writes the passed uint16 in little
// endian and advances the current slice.
func (eb *EfficientBuffer) PutUint16(v uint16) {
	binary.LittleEndian.PutUint16((*eb)[:2], v)
	*eb = (*eb)[2:]
}

// PutInt16 writes the passed int16 in little
// endian and advances the current slice.
func (eb *EfficientBuffer) PutInt16(v int16) {
	binary.LittleEndian.PutUint16((*eb)[:2], uint16(v))
	*eb = (*eb)[2:]
}

// PutUint8 writes the passed uint8 in little
// endian and advances the current slice.
func (eb *EfficientBuffer) PutUint8(v uint8) {
	(*eb)[0] = v
	*eb = (*eb)[1:]
}
