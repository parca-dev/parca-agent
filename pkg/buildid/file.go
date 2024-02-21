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

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package buildid

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
)

var elfPrefix = []byte("\x7fELF")

var readSize = 32 * 1024 // changed for testing

// FromFile reads the build ID from a binary by opening the file,
// but only reading the first 32 kB of the file.
// It also treats Go binaries specially, reading the build ID from
// designated sections.
// ELF binaries store the build ID in a proper PT_NOTE section.
func FromFile(f *os.File) (id string, err error) { //nolint:nonamedreturns
	// Read the first 32 kB of the binary file.
	// That should be enough to find the build ID.
	// In ELF files, the build ID is in the leading headers,
	// which are typically less than 4 kB, not to mention 32 kB.
	data := make([]byte, readSize)
	r := io.NewSectionReader(f, 0, int64(readSize))
	_, err = io.ReadFull(r, data)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	if err != nil {
		return "", err
	}

	if bytes.HasPrefix(data, elfPrefix) {
		return readELF(f.Name(), f, data)
	}
	return readRaw(data)
}

var (
	goBuildPrefix = []byte("\xff Go build ID: \"")
	goBuildEnd    = []byte("\"\n \xff")
)
var errBuildIDMalformed = errors.New("malformed object file")

// readRaw finds the raw build ID stored in text segment data.
func readRaw(data []byte) (id string, err error) { //nolint:nonamedreturns
	i := bytes.Index(data, goBuildPrefix)
	if i < 0 {
		// Missing. Treat as successful but build ID empty.
		return "", nil
	}

	j := bytes.Index(data[i+len(goBuildPrefix):], goBuildEnd)
	if j < 0 {
		return "", &fs.PathError{Op: "parse", Err: errBuildIDMalformed}
	}

	quoted := data[i+len(goBuildPrefix)-1 : i+len(goBuildPrefix)+j+1]
	id, err = strconv.Unquote(string(quoted))
	if err != nil {
		return "", &fs.PathError{Op: "parse", Err: errBuildIDMalformed}
	}
	return id, nil
}

var (
	elfGoNote  = []byte("Go\x00\x00")
	elfGNUNote = []byte("GNU\x00")
)

// The Go build ID is stored in a note described by an ELF PT_NOTE prog
// header. The caller has already opened filename, to get f, and read
// at least 4 kB out, in data.
func readELF(name string, r io.ReadSeeker, data []byte) (buildid string, err error) { //nolint:nonamedreturns
	// Assume the note content is in the data, already read.
	// Rewrite the ELF header to set shoff and shnum to 0, so that we can pass
	// the data to elf.NewFile and it will decode the Prog list but not
	// try to read the section headers and the string table from disk.
	// That's a waste of I/O when all we care about is the Prog list
	// and the one ELF note.
	switch elf.Class(data[elf.EI_CLASS]) {
	case elf.ELFCLASS32:
		data[32], data[33], data[34], data[35] = 0, 0, 0, 0
		data[48] = 0
		data[49] = 0
	case elf.ELFCLASS64:
		data[40], data[41], data[42], data[43] = 0, 0, 0, 0
		data[44], data[45], data[46], data[47] = 0, 0, 0, 0
		data[60] = 0
		data[61] = 0
	case elf.ELFCLASSNONE:
	}

	const elfGoBuildIDTag = 4
	const gnuBuildIDTag = 3

	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", &fs.PathError{Path: name, Op: "parse", Err: err}
	}
	var gnu []byte
	for _, p := range ef.Progs {
		if p.Type != elf.PT_NOTE || p.Filesz < 16 {
			continue
		}

		var note []byte
		if p.Off+p.Filesz < uint64(len(data)) {
			note = data[p.Off : p.Off+p.Filesz]
		} else {
			// For some linkers, such as the Solaris linker,
			// the buildid may not be found in data (which
			// likely contains the first 16kB of the file)
			// or even the first few megabytes of the file
			// due to differences in note segment placement;
			// in that case, extract the note data manually.
			_, err = r.Seek(int64(p.Off), io.SeekStart)
			if err != nil {
				return "", err
			}

			note = make([]byte, p.Filesz)
			_, err = io.ReadFull(r, note)
			if err != nil {
				return "", err
			}
		}

		filesz := p.Filesz
		off := p.Off
		for filesz >= 16 {
			nameSize := ef.ByteOrder.Uint32(note)
			valSize := ef.ByteOrder.Uint32(note[4:])
			tag := ef.ByteOrder.Uint32(note[8:])
			nname := note[12:16]
			if nameSize == 4 && 16+valSize <= uint32(len(note)) && tag == elfGoBuildIDTag && bytes.Equal(nname, elfGoNote) {
				return string(note[16 : 16+valSize]), nil
			}

			if nameSize == 4 && 16+valSize <= uint32(len(note)) && tag == gnuBuildIDTag && bytes.Equal(nname, elfGNUNote) {
				gnu = note[16 : 16+valSize]
			}

			nameSize = (nameSize + 3) &^ 3
			valSize = (valSize + 3) &^ 3
			notesz := uint64(12 + nameSize + valSize)
			if filesz <= notesz {
				break
			}
			off += notesz
			align := p.Align
			alignedOff := (off + align - 1) &^ (align - 1)
			notesz += alignedOff - off
			off = alignedOff
			filesz -= notesz
			note = note[notesz:]
		}
	}

	// If we didn't find a Go note, use a GNU note if available.
	// This is what gccgo uses.
	if len(gnu) > 0 {
		return hex.EncodeToString(gnu), nil
	}

	// No note. Treat as successful but build ID empty.
	return "", nil
}
