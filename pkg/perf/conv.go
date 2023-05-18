// Copyright 2023 The Parca Authors
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

package perf

import "unsafe"

func newStringConverter(capacity int) *stringConverter {
	conv := stringConverter{}
	if capacity <= 0 {
		return &conv
	}

	conv.buf = make([]byte, 0, capacity)
	return &conv
}

// stringConverter converts bytes to strings with less allocs.
// The idea is to accumulate bytes in a buffer with specified capacity
// and create strings with unsafe.String using bytes from a buffer.
// For example, 10 "fizz" strings written to a 40-byte buffer
// will result in 1 alloc instead of 10.
//
// Once a buffer is filled, strings will be allocated as usually.
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
	if len(c.buf)+n > cap(c.buf) {
		return string(b)
	}

	c.buf = append(c.buf, b...)
	b = c.buf[c.offset:]
	s := unsafe.String(&b[0], n)
	c.offset += n

	return s
}
