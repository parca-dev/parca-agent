// Copyright (c) 2022 The Parca Authors
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

// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elfreader

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	maxNoteSize        = 1 << 20 // in bytes
	NoteTypeGNUBuildID = 3
	NoteTypeGoBuildID  = 4
)

// ElfNote is the payload of a Note Section in an ELF file.
type ElfNote struct {
	Name string // Contents of the "name" field, omitting the trailing zero byte.
	Desc []byte // Contents of the "desc" field.
	Type uint32 // Contents of the "type" field.
}

// ParseNotes returns the notes from a SHT_NOTE section or PT_NOTE segment.
func ParseNotes(reader io.Reader, alignment int, order binary.ByteOrder) ([]ElfNote, error) {
	r := bufio.NewReader(reader)

	// padding returns the number of bytes required to pad the given size to an
	// alignment boundary.
	padding := func(size int) int {
		return ((size + (alignment - 1)) &^ (alignment - 1)) - size
	}

	var notes []ElfNote
	for {
		noteHeader := make([]byte, 12) // 3 4-byte words
		if _, err := io.ReadFull(r, noteHeader); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		namesz := order.Uint32(noteHeader[0:4])
		descsz := order.Uint32(noteHeader[4:8])
		typ := order.Uint32(noteHeader[8:12])

		if uint64(namesz) > uint64(maxNoteSize) {
			return nil, fmt.Errorf("note name too long (%d bytes)", namesz)
		}
		var name string
		if namesz > 0 {
			// Documentation differs as to whether namesz is meant to include the
			// trailing zero, but everyone agrees that name is null-terminated.
			// So we'll just determine the actual length after the fact.
			var err error
			name, err = r.ReadString('\x00')
			if err == io.EOF {
				return nil, fmt.Errorf("missing note name (want %d bytes)", namesz)
			} else if err != nil {
				return nil, err
			}
			namesz = uint32(len(name))
			name = name[:len(name)-1]
		}

		// Drop padding bytes until the desc field.
		for n := padding(len(noteHeader) + int(namesz)); n > 0; n-- {
			if _, err := r.ReadByte(); err == io.EOF {
				return nil, fmt.Errorf(
					"missing %d bytes of padding after note name", n)
			} else if err != nil {
				return nil, err
			}
		}

		if uint64(descsz) > uint64(maxNoteSize) {
			return nil, fmt.Errorf("note desc too long (%d bytes)", descsz)
		}
		desc := make([]byte, int(descsz))
		if _, err := io.ReadFull(r, desc); errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("missing desc (want %d bytes)", len(desc))
		} else if err != nil {
			return nil, err
		}

		notes = append(notes, ElfNote{Name: name, Desc: desc, Type: typ})

		// Drop padding bytes until the next note or the end of the section,
		// whichever comes first.
		for n := padding(len(desc)); n > 0; n-- {
			if _, err := r.ReadByte(); err == io.EOF {
				// We hit the end of the section before an alignment boundary.
				// This can happen if this section is at the end of the file or the next
				// section has a smaller alignment requirement.
				break
			} else if err != nil {
				return nil, err
			}
		}
	}
	return notes, nil
}
