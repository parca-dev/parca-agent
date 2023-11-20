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

type entry struct {
	offset uint32
	length uint32
}

type StringTable struct {
	data    []byte
	entries []entry

	dict map[string]int
}

func NewStringTable(dataCapacity, entriesCapacity int) *StringTable {
	return &StringTable{
		data:    make([]byte, 0, dataCapacity),
		entries: make([]entry, 0, entriesCapacity),
		dict:    make(map[string]int),
	}
}

func (t *StringTable) GetOrAdd(s []byte) int {
	if i, ok := t.dict[unsafeString(s)]; ok {
		return i
	}

	offset := uint32(len(t.data))
	t.data = append(t.data, s...)
	t.entries = append(t.entries, entry{
		offset: offset,
		length: uint32(len(s)),
	})
	i := len(t.entries) - 1
	t.dict[string(s)] = i
	return i
}

func unsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func (t *StringTable) Get(i int) string {
	return string(t.GetBytes(i))
}

func (t *StringTable) LengthOf(i int) uint32 {
	return t.entries[i].length
}

func (t *StringTable) Len() int {
	return len(t.entries)
}

func (t *StringTable) DataLength() int {
	return len(t.data)
}

func (t *StringTable) GetBytes(i int) []byte {
	e := t.entries[i]
	return t.data[e.offset : e.offset+e.length]
}
