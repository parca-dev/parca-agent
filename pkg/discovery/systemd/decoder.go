// Copyright 2023-2024 The Parca Authors
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

package systemd

import (
	"bytes"
	"encoding/binary"
	"io"
	"unsafe"
)

// newDecoder creates a new D-Bus decoder.
// By default it expects the little-endian byte order
// and assumes a zero offset to start counting bytes read from src.
func newDecoder(src io.Reader) *decoder {
	return &decoder{
		order:  binary.LittleEndian,
		src:    src,
		buf:    &bytes.Buffer{},
		offset: 0,
	}
}

type decoder struct {
	order binary.ByteOrder
	src   io.Reader
	buf   *bytes.Buffer
	// offset is a current position in the message
	// which is used solely to determine the alignment.
	// The offset is limited by maxMessageSize.
	offset uint32
}

// Reset resets the decoder to be reading from src
// with zero offset.
func (d *decoder) Reset(src io.Reader) {
	d.src = src
	d.offset = 0
}

// SetOrder sets a byte order used in decoding.
func (d *decoder) SetOrder(order binary.ByteOrder) {
	d.order = order
}

// Align advances the decoder by discarding the alignment padding.
func (d *decoder) Align(n uint32) error {
	offset, padding := nextOffset(d.offset, n)
	if padding == 0 {
		return nil
	}

	_, err := readN(d.src, d.buf, int(padding))
	d.offset = offset
	return err
}

// ReadN reads exactly n bytes without decoding.
func (d *decoder) ReadN(n uint32) ([]byte, error) {
	d.offset += n
	return readN(d.src, d.buf, int(n))
}

// Byte decodes D-Bus BYTE.
func (d *decoder) Byte() (byte, error) {
	b, err := readN(d.src, d.buf, 1)
	if err != nil {
		return 0, err
	}

	d.offset++
	return b[0], nil
}

const u32size = 4

// Uint32 decodes D-Bus UINT32.
func (d *decoder) Uint32() (uint32, error) {
	err := d.Align(u32size)
	if err != nil {
		return 0, err
	}

	b, err := readN(d.src, d.buf, u32size)
	if err != nil {
		return 0, err
	}

	u := d.order.Uint32(b)
	// 4 bytes were read because uint32 takes 4 bytes.
	d.offset += u32size
	return u, nil
}

// String decodes D-Bus STRING or OBJECT_PATH.
// A caller must not retain the returned byte slice.
// The string conversion is not done here to avoid allocations.
func (d *decoder) String() ([]byte, error) {
	strLen, err := d.Uint32()
	if err != nil {
		return nil, err
	}

	// Read the string content
	// accounting for a null byte at the end of the string.
	b, err := readN(d.src, d.buf, int(strLen)+1)
	if err != nil {
		return nil, err
	}
	d.offset += strLen + 1

	return b[:strLen], nil
}

// Signature decodes D-Bus SIGNATURE
// which is the same as STRING except the length is a single byte
// (thus signatures have a maximum length of 255).
func (d *decoder) Signature() ([]byte, error) {
	strLen, err := d.Byte()
	if err != nil {
		return nil, err
	}

	// Read the string content
	// accounting for a null byte at the end of the string.
	b, err := readN(d.src, d.buf, int(strLen)+1)
	if err != nil {
		return nil, err
	}
	d.offset += uint32(strLen) + 1

	return b[:strLen], nil
}

// readN reads exactly n bytes from src into the buffer.
// The buffer grows on demand.
// The objective is to reduce memory allocs.
func readN(src io.Reader, buf *bytes.Buffer, n int) ([]byte, error) {
	buf.Reset()
	buf.Grow(n)
	b := buf.Bytes()[:n]

	// Since src is buffered, a single Read call
	// doesn't guarantee that all required n bytes will be read.
	// The second Read call fetches the remaining bytes.
	//
	// If the requested n bytes don't fit into src' buffer,
	// it doesn't buffer them, so there can't be three calls.
	//
	// Reading in a loop would simplify the reasoning,
	// but it works 8.51% slower for DecodeString, and 4.23% for DecodeListUnits.
	var (
		k   int
		err error
	)
	if k, err = src.Read(b); err != nil {
		return nil, err
	}
	if k != n {
		_, err = src.Read(b[k:])
	}

	return b, err
}

// nextOffset returns the next byte position and the padding
// according to the current offset and alignment requirement.
func nextOffset(current, align uint32) (uint32, uint32) {
	if current%align == 0 {
		return current, 0
	}

	next := (current + align - 1) & ^(align - 1)
	padding := next - current
	return next, padding
}

func newStringConverter(capacity int) *stringConverter {
	return &stringConverter{
		buf:    make([]byte, 0, capacity),
		offset: 0,
	}
}

// stringConverter converts bytes to strings with less allocs.
// The idea is to accumulate bytes in a buffer with specified capacity
// and create strings with unsafe.String using bytes from a buffer.
// For example, 10 "fizz" strings written to a 40-byte buffer
// will result in 1 alloc instead of 10.
//
// Once a buffer is filled, a new one is created with the same capacity.
// Old buffers will be eventually GC-ed
// with no side effects to the returned strings.
type stringConverter struct {
	// buf is a temporary buffer where decoded strings are batched.
	buf []byte
	// offset is a buffer position where the last string was written.
	offset int
}

// String converts bytes to a string.
func (c *stringConverter) String(b []byte) string {
	n := len(b)
	if n == 0 {
		return ""
	}
	// Must allocate because a string doesn't fit into the buffer.
	if n > cap(c.buf) {
		return string(b)
	}

	if len(c.buf)+n > cap(c.buf) {
		c.buf = make([]byte, 0, cap(c.buf))
		c.offset = 0
	}
	c.buf = append(c.buf, b...)

	b = c.buf[c.offset:]
	s := unsafe.String(&b[0], n)
	c.offset += n
	return s
}
