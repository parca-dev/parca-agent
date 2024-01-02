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
	"encoding/hex"
	"fmt"
)

// newEncoder creates a new D-Bus encoder.
// By default it uses the little-endian byte order
// and assumes a zero offset to start counting written bytes.
func newEncoder(dst *bytes.Buffer) *encoder {
	return &encoder{
		order:  binary.LittleEndian,
		dst:    dst,
		offset: 0,
	}
}

type encoder struct {
	order binary.ByteOrder
	dst   *bytes.Buffer
	// pad must always contain zeroes to add padding to dst.
	pad [8]byte
	// buf is a buffer that is used to encode integers.
	buf [4]byte
	// offset is a current position in the encoded message
	// which is used solely to determine the alignment.
	// The offset is limited by maxMessageSize.
	offset uint32
}

// Reset resets the encoder to be writing into dst
// starting with zero offset.
func (e *encoder) Reset(dst *bytes.Buffer) {
	e.dst = dst
	e.offset = 0
}

// Offset returns a current position in the encoded message.
func (e *encoder) Offset() uint32 {
	return e.offset
}

// Align adds the alignment padding.
func (e *encoder) Align(n uint32) {
	offset, padding := nextOffset(e.offset, n)
	if padding == 0 {
		return
	}

	e.dst.Write(e.pad[:padding])
	e.offset = offset
}

// Byte encodes D-Bus BYTE.
func (e *encoder) Byte(b byte) {
	e.dst.WriteByte(b)
	e.offset++
}

// Uint32 encodes D-Bus UINT32.
func (e *encoder) Uint32(u uint32) {
	e.Align(u32size)

	b := e.buf[:u32size]
	e.order.PutUint32(b, u)
	e.dst.Write(b)
	// 4 bytes were written because uint32 takes 4 bytes.
	e.offset += u32size
}

// Uint32At encodes UINT32 at the given offset.
// This is useful when overwriting a header field such as FieldsLen
// because it is not known in advance.
func (e *encoder) Uint32At(u, offset uint32) error {
	if int(offset) >= e.dst.Len() {
		return fmt.Errorf("offset is out of range: %d/%d", offset, e.dst.Len())
	}

	b := e.buf[:u32size]
	e.order.PutUint32(b, u)

	// Overwrite 4 bytes of encoded uint32 in the dst
	// starting from the offset.
	dst := e.dst.Bytes()
	copy(dst[offset:], b)
	return nil
}

// String encodes D-Bus STRING or OBJECT_PATH.
func (e *encoder) String(s string) {
	strLen := len(s)
	e.Uint32(uint32(strLen))

	e.dst.WriteString(s)
	// Account for a null byte at the end of the string.
	e.dst.WriteByte(0)
	e.offset += uint32(strLen + 1)
}

// Signature encodes D-Bus SIGNATURE
// which is the same as STRING except the length is a single byte
// (thus signatures have a maximum length of 255).
func (e *encoder) Signature(s string) {
	strLen := len(s)
	e.Byte(byte(strLen))

	e.dst.WriteString(s)
	// Account for a null byte at the end of the string.
	e.dst.WriteByte(0)
	e.offset += uint32(strLen + 1)
}

// escapeBusLabel escapes a bus label such as a unit name.
// Given a string s, all characters which are not ASCII alphanumerics
// are replaced by C-style "\x2d" escapes.
// If the first character is a numeric, it's also escaped.
//
// See https://github.com/systemd/systemd/blob/main/src/basic/bus-label.c.
func escapeBusLabel(s string, buf *bytes.Buffer) {
	if len(s) == 0 {
		buf.WriteRune('_')
		return
	}

	// First two bytes are for the char hex,
	// and the third byte is an ASCII char to encode.
	b := [3]byte{}
	dst := b[:2]
	src := b[2:]

	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(i, c) {
			b[2] = c
			hex.Encode(dst, src)
			buf.WriteByte('_')
			buf.Write(dst)
		} else {
			buf.WriteByte(c)
		}
	}
}

func shouldEscape(i int, c byte) bool {
	switch {
	case i > 0 && '0' <= c && c <= '9':
		return false
	case 'A' <= c && c <= 'Z':
		return false
	case 'a' <= c && c <= 'z':
		return false
	default:
		return true
	}
}
