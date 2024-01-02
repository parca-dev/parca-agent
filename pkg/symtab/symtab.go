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

package symtab

import (
	"bufio"
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
	headerSize = uint32(unsafe.Sizeof(FileHeader{}))
	entrySize  = uint32(8 + 4 + 2) // uint64, uint32, uint16
)

var (
	ErrSymbolNotFound   = errors.New("symbol not found")
	ErrAlreadyFinalized = errors.New("already finalized")
	ErrBadMagic         = errors.New("bad magic identifier")
	ErrBadVersion       = errors.New("bad version")
	ErrReadZeroBytes    = errors.New("read zero bytes")
)

type FileHeader struct {
	Magic           uint32
	Version         uint32
	AddressesOffset uint32
	AddressesCount  uint32
}

type Entry struct {
	Address uint64
	Offset  uint32
	Len     uint16
}

type FileWriter struct {
	file         *os.File
	w            *bufio.Writer
	entries      []Entry
	stringOffset uint32
	finalized    bool
	entryBuf     []byte
	entryCount   uint32
}

func NewWriter(path string, preallocate int) (*FileWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	// Write dummy header. We'll write the right header once we have
	// written all the data.
	err = binary.Write(file, binary.LittleEndian, FileHeader{})
	if err != nil {
		return nil, fmt.Errorf("binary.Write: %w", err)
	}
	return &FileWriter{
		file:     file,
		w:        bufio.NewWriter(file),
		entries:  make([]Entry, 0, preallocate),
		entryBuf: make([]byte, entrySize),
	}, nil
}

func (fw *FileWriter) AddSymbol(name string, address uint64) error {
	stringOffset, err := fw.AddString(name)
	if err != nil {
		return err
	}

	fw.AddEntry(Entry{
		Address: address,
		Offset:  stringOffset,
		Len:     uint16(len(name)),
	})
	return nil
}

func (fw *FileWriter) AddEntry(entry Entry) {
	fw.entries = append(fw.entries, entry)
}

func (fw *FileWriter) AddString(name string) (uint32, error) {
	if fw.finalized {
		return 0, ErrAlreadyFinalized
	}

	_, err := fw.w.WriteString(name)
	if err != nil {
		return 0, fmt.Errorf("WriteString: %w", err)
	}
	// Append nil to make debugging easier.
	_, err = fw.w.WriteString("\000")
	if err != nil {
		return 0, fmt.Errorf("WriteString: %w", err)
	}

	offset := fw.stringOffset
	fw.stringOffset += uint32(len(name) + 1)
	return offset, nil
}

func (fw *FileWriter) WriteHeader() error {
	if err := fw.w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	if _, err := fw.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("file.Seek: %w", err)
	}
	if err := binary.Write(fw.w, binary.LittleEndian, &FileHeader{
		Magic:           MAGIC,
		Version:         VERSION,
		AddressesOffset: fw.stringOffset,
		AddressesCount:  fw.entryCount,
	}); err != nil {
		return fmt.Errorf("binary.Write: %w", err)
	}
	return nil
}

func (fw *FileWriter) Write() error {
	if fw.finalized {
		return ErrAlreadyFinalized
	}
	defer fw.Close()

	// Sort and write entries.
	sort.Slice(fw.entries, func(i, j int) bool {
		return fw.entries[i].Address < fw.entries[j].Address
	})

	for _, Entry := range fw.entries {
		if err := fw.WriteEntry(Entry); err != nil {
			return fmt.Errorf("binary.Write: %w", err)
		}
	}

	if err := fw.WriteHeader(); err != nil {
		return fmt.Errorf("writeHeader: %w", err)
	}

	return nil
}

func (fw *FileWriter) Close() error {
	if err := fw.w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	fw.finalized = true

	return fw.file.Close()
}

func (fw *FileWriter) WriteEntry(e Entry) error {
	binary.LittleEndian.PutUint64(fw.entryBuf[:8], e.Address)
	binary.LittleEndian.PutUint32(fw.entryBuf[8:12], e.Offset)
	binary.LittleEndian.PutUint16(fw.entryBuf[12:14], e.Len)

	if _, err := fw.w.Write(fw.entryBuf); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	fw.entryCount++

	return nil
}

func readEntry(buf []byte) Entry {
	return Entry{
		Address: binary.LittleEndian.Uint64(buf[:8]),
		Offset:  binary.LittleEndian.Uint32(buf[8:12]),
		Len:     binary.LittleEndian.Uint16(buf[12:14]),
	}
}

type FileReader struct {
	reader      *mmap.ReaderAt
	header      *FileHeader
	entryBuffer []byte
}

func validateHeader(path string) (*FileHeader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("os.Open: %w", err)
	}
	defer f.Close()
	header := FileHeader{}
	err = binary.Read(f, binary.LittleEndian, &header)
	if err != nil {
		return nil, fmt.Errorf("binary.Read: %w", err)
	}

	if header.Magic != MAGIC {
		return nil, ErrBadMagic
	}
	if header.Version != VERSION {
		return nil, ErrBadVersion
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

func (fr *FileReader) Header() FileHeader {
	return *fr.header
}

func (fr *FileReader) Close() error {
	return fr.reader.Close()
}

func (fr *FileReader) readEntry(at uint32) (*Entry, error) {
	read, err := fr.reader.ReadAt(fr.entryBuffer, int64(at))
	if err != nil {
		return nil, fmt.Errorf("mmap ReadAt: %w", err)
	}
	if read == 0 {
		return nil, ErrReadZeroBytes
	}

	entry := readEntry(fr.entryBuffer)
	return &entry, nil
}

func (fr *FileReader) entry(address uint64) (*Entry, error) {
	left := uint32(0)
	right := fr.header.AddressesCount
	var found *Entry

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
		if entry.Address <= address {
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
		return "", ErrSymbolNotFound
	}

	offset := uint32(unsafe.Sizeof(FileHeader{})) + entry.Offset
	buffer := make([]byte, entry.Len)

	read, err := fr.reader.ReadAt(buffer, int64(offset))
	if err != nil {
		return "", fmt.Errorf("mmap.ReadAt: %w", err)
	}
	if read == 0 {
		return "", ErrReadZeroBytes
	}

	return unsafeString(buffer), nil
}

// unsafeString avoids memory allocations by directly casting
// the memory area that we know contains a valid string to a
// string pointer.
func unsafeString(b []byte) string {
	return *((*string)(unsafe.Pointer(&b)))
}
