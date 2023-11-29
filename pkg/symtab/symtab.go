// Copyright 2022-2023 The Parca Authors
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

package symtab

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"unsafe"

	"golang.org/x/exp/mmap"
)

// There are several use-cases, such as symbolization, that conceptually boil
// down to a list of tuples, each formed of an identifier and a string, where
// we want to efficiently find the string for a particular identifier.
//
// A possible approach to solve this problem is to create a large list
// in memory, sorted by identifier, so we can binary-search over the ids
// and find the entry for which entry_i.Id <= Id < entry_i+1.Id.
//
// While this works well and it's easy to understand and maintain, when
// the list grows too large, this can be a large source of retained memory.
// This issue is particularly bad when memory offloading (swap/zswap) is not
// enabled, as the "cold" anonymous memory won't have a way to be moved to
// secondary storage.
//
// This implementation produces a simple binary format that's easy to write
// and read, but most importantly, it should be efficient to query.
//
// ┌─────────┬────────────────────────────┬────────────────────────────────────────────┐
// │         │                            │                                            │
// │ Header  │  Strings with nul endings  │  Sorted ids + meta information on strings  │
// │         │                            │                                            │
// └─────────┴────────────────────────────┴────────────────────────────────────────────┘
//
// The strings aren't deduplicated or optimized in any way, to reduce the memory
// usage during the write phase.
//
// The file is read with `mmap(2)`, to avoid performing any read system calls
// while binary searching over the identifiers, and leveraging the caching layer
// of the filesystem. As we now have a backing file, rather than being anonymous
// memory, the OS can remove cached pages if there's need for more memory.

const (
	MAGIC      = uint32(0x8A4CA)
	VERSION    = uint32(1)
	headerSize = uint32(unsafe.Sizeof(fileHeader{}))
	entrySize  = uint32(8 + 4 + 2) // uint64, uint32, uint16
)

var (
	errSymbolNotFound   = errors.New("symbol not found")
	errAlreadyFinalized = errors.New("already finalized")
	errBadMagic         = errors.New("bad magic identifier")
	errBadVersion       = errors.New("bad version")
	errReadZeroBytes    = errors.New("read zero bytes")
)

type fileHeader struct {
	Magic           uint32
	Version         uint32
	AddressesOffset uint32
	AddressesCount  uint32
}

type entry struct {
	address uint64
	offset  uint32
	len     uint16
}

type FileWriter struct {
	file         *os.File
	entries      []entry
	stringOffset uint32
	finalized    bool
}

func NewWriter(path string, preallocate int) (*FileWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	// Write dummy header. We'll write the right header once we have
	// written all the data.
	err = binary.Write(file, binary.LittleEndian, fileHeader{})
	if err != nil {
		return nil, fmt.Errorf("binary.Write: %w", err)
	}
	return &FileWriter{
		file:    file,
		entries: make([]entry, 0, preallocate),
	}, nil
}

func (fw *FileWriter) AddSymbol(name string, address uint64) error {
	if fw.finalized {
		return errAlreadyFinalized
	}

	_, err := fw.file.WriteString(name)
	if err != nil {
		return fmt.Errorf("WriteString: %w", err)
	}
	// Append nil to make debugging easier.
	_, err = fw.file.WriteString("\000")
	if err != nil {
		return fmt.Errorf("WriteString: %w", err)
	}

	fw.entries = append(fw.entries, entry{
		address: address,
		offset:  fw.stringOffset,
		len:     uint16(len(name)),
	})

	fw.stringOffset += uint32(len(name) + 1)
	return nil
}

func (fw *FileWriter) writeHeader() error {
	_, err := fw.file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("file.Seek: %w", err)
	}
	err = binary.Write(fw.file, binary.LittleEndian, &fileHeader{
		Magic:           MAGIC,
		Version:         VERSION,
		AddressesOffset: fw.stringOffset,
		AddressesCount:  uint32(len(fw.entries)),
	})
	if err != nil {
		return fmt.Errorf("binary.Write: %w", err)
	}
	return nil
}

func (fw *FileWriter) Write() error {
	if fw.finalized {
		return errAlreadyFinalized
	}
	defer func() {
		fw.file.Close()
		fw.finalized = true
	}()

	// Sort and write entries.
	sort.Slice(fw.entries, func(i, j int) bool {
		return fw.entries[i].address < fw.entries[j].address
	})

	for _, entry := range fw.entries {
		err := binary.Write(fw.file, binary.LittleEndian, entry)
		if err != nil {
			return fmt.Errorf("binary.Write: %w", err)
		}
	}

	err := fw.writeHeader()
	if err != nil {
		return fmt.Errorf("writeHeader: %w", err)
	}

	return nil
}

type FileReader struct {
	reader      *mmap.ReaderAt
	header      *fileHeader
	entryBuffer []byte
}

func validateHeader(path string) (*fileHeader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("os.Open: %w", err)
	}
	defer f.Close()
	header := fileHeader{}
	err = binary.Read(f, binary.LittleEndian, &header)
	if err != nil {
		return nil, fmt.Errorf("binary.Read: %w", err)
	}

	if header.Magic != MAGIC {
		return nil, errBadMagic
	}
	if header.Version != VERSION {
		return nil, errBadVersion
	}

	return &header, nil
}

func NewReader(path string) (*FileReader, error) {
	reader, err := mmap.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mmap.Open: %w", err)
	}
	header, err := validateHeader(path)
	if err != nil {
		return nil, fmt.Errorf("validateHeader: %w", err)
	}

	return &FileReader{
		reader:      reader,
		header:      header,
		entryBuffer: make([]byte, entrySize),
	}, nil
}

func (fr *FileReader) Close() error {
	return fr.reader.Close()
}

func (fr *FileReader) readEntry(at uint32) (*entry, error) {
	read, err := fr.reader.ReadAt(fr.entryBuffer, int64(at))
	if err != nil {
		return nil, fmt.Errorf("mmap ReadAt: %w", err)
	}
	if read == 0 {
		return nil, errReadZeroBytes
	}

	entry := entry{
		address: binary.LittleEndian.Uint64(fr.entryBuffer[0:8]),
		offset:  binary.LittleEndian.Uint32(fr.entryBuffer[8:12]),
		len:     binary.LittleEndian.Uint16(fr.entryBuffer[12:14]),
	}

	return &entry, nil
}

func (fr *FileReader) entry(address uint64) (*entry, error) {
	left := uint32(0)
	right := fr.header.AddressesCount
	var found *entry

	for {
		mid := (left + right) / 2
		absoluteMid := headerSize + fr.header.AddressesOffset + entrySize*mid

		if left >= right {
			break
		}

		entry, err := fr.readEntry(absoluteMid)
		if err != nil {
			return nil, fmt.Errorf("readEntry: %w", err)
		}
		if entry.address <= address {
			found = entry
			left = mid + 1
		} else {
			right = mid
		}
	}

	return found, nil
}

func (fr *FileReader) Symbolize(address uint64) (string, error) {
	entry, err := fr.entry(address)
	if err != nil {
		return "", fmt.Errorf("entry: %w", err)
	}
	if entry == nil {
		return "", errSymbolNotFound
	}

	offset := uint32(unsafe.Sizeof(fileHeader{})) + entry.offset
	buffer := make([]byte, entry.len)

	read, err := fr.reader.ReadAt(buffer, int64(offset))
	if err != nil {
		return "", fmt.Errorf("mmap.ReadAt: %w", err)
	}
	if read == 0 {
		return "", errReadZeroBytes
	}

	return unsafeString(buffer), nil
}

// unsafeString avoids memory allocations by directly casting
// the memory area that we know contains a valid string to a
// string pointer.
func unsafeString(b []byte) string {
	return *((*string)(unsafe.Pointer(&b)))
}
