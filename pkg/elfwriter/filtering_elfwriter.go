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
//

package elfwriter

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/rzajac/flexbuf"
)

// FilteringWriter is a wrapper around Writer that allows to filter out sections,
// and programs from the source. Then write them to underlying io.WriteSeeker.
type FilteringWriter struct {
	Writer
	src SeekReaderAt

	progPredicates          []func(*elf.Prog) bool
	sectionPredicates       []func(*elf.Section) bool
	sectionHeaderPredicates []func(*elf.Section) bool
}

// NewFromSource creates a new Writer using given source.
func NewFromSource(dst io.WriteSeeker, src SeekReaderAt, opts ...Option) (*FilteringWriter, error) {
	f, err := elf.NewFile(src)
	if err != nil {
		return nil, fmt.Errorf("error reading ELF file: %w", err)
	}
	defer f.Close()

	w, err := newWriter(dst, &f.FileHeader, newSectionWriterWithRawSource(&f.FileHeader, src), opts...)
	if err != nil {
		return nil, err
	}
	w.progs = f.Progs
	w.sections = f.Sections
	return &FilteringWriter{
		Writer: *w,
		src:    src,
	}, nil
}

// FilterPrograms filters out programs from the source.
func (w *FilteringWriter) FilterPrograms(predicates ...func(*elf.Prog) bool) {
	w.progPredicates = append(w.progPredicates, predicates...)
}

// FilterSections filters out sections from the source.
// If sections have links to other sections, the referred sections are also be carried over to the destination.
func (w *FilteringWriter) FilterSections(predicates ...func(*elf.Section) bool) {
	w.sectionPredicates = append(w.sectionPredicates, predicates...)
}

// FilterHeaderOnlySections filters out header only sections from the source.
func (w *FilteringWriter) FilterHeaderOnlySections(predicates ...func(*elf.Section) bool) {
	w.sectionHeaderPredicates = append(w.sectionHeaderPredicates, predicates...)
}

func (w *FilteringWriter) Flush() error {
	if len(w.progPredicates) > 0 {
		newProgs := []*elf.Prog{}
		for _, prog := range w.progs {
			if match(prog, w.progPredicates...) {
				newProgs = append(newProgs, prog)
			}
		}
		w.progs = newProgs
	}

	newSections := []*elf.Section{}
	if len(w.sectionPredicates) > 0 {
		addedSections := make(map[string]struct{})
		for _, sec := range w.sections {
			if match(sec, w.sectionPredicates...) {
				newSections = append(newSections, sec)
				addedSections[sec.Name] = struct{}{}
			}
		}
		srcTgt := make(map[string]string)
		tgtSrc := make(map[string]string)
		linkPred := func(sec *elf.Section) bool {
			_, ok := tgtSrc[sec.Name]
			return ok
		}

		for _, sec := range newSections {
			if sec.Link != 0 {
				tgtSrc[w.sections[sec.Link].Name] = sec.Name
				srcTgt[sec.Name] = w.sections[sec.Link].Name
			}
		}
	loop:
		for _, sec := range w.sections {
			if match(sec, linkPred) {
				_, ok := addedSections[sec.Name]
				if !ok {
					newSections = append(newSections, sec)
					addedSections[sec.Name] = struct{}{}
					if sec.Link != 0 {
						tgtSrc[w.sections[sec.Link].Name] = sec.Name
						srcTgt[sec.Name] = w.sections[sec.Link].Name
						continue loop
					}
				}
			}
		}
		w.sectionLinks = srcTgt
	}

	if len(w.sectionHeaderPredicates) > 0 {
		newSectionHeaders := make([]elf.SectionHeader, 0, len(w.sectionHeaders))
		for _, sec := range w.sections {
			if match(sec, w.sectionHeaderPredicates...) {
				newSectionHeaders = append(newSectionHeaders, sec.SectionHeader)
			}
		}
		w.sectionHeaders = newSectionHeaders
	}

	w.sections = newSections

	return w.Writer.Flush()
}

func match[T *elf.Prog | *elf.Section | *elf.SectionHeader](elem T, predicates ...func(T) bool) bool {
	for _, pred := range predicates {
		if pred(elem) {
			return true
		}
	}
	return false
}

func newSectionWriterWithRawSource(fhdr *elf.FileHeader, src SeekReaderAt) sectionWriterFn {
	return func(w io.Writer, sec *elf.Section) error {
		// Opens the header. If it is compressed, it will un-compress it.
		// If compressed, it will skip past the compression header [1] and
		// give a reader to the section itself.
		//
		// - [1] https://github.com/golang/go/blob/cd33b4089caf362203cd749ee1b3680b72a8c502/src/debug/elf/file.go#L132
		r := sec.Open()
		if sec.Type == elf.SHT_NOBITS {
			r = io.NewSectionReader(&zeroReader{}, 0, 0)
		}
		// elf.Section.Open() returns a reader that already handles the edge cases of
		// compressed sections. e.g. if the flag SHF_COMPRESSED is set incorrectly,
		// it will still try to set comprssion header by reading the first 12 bytes,
		// and return a correct reader.
		// In this case the returned reader offset: sec.Offset + 12, and size: sec.FileSize - 12.
		if sec.Flags&elf.SHF_COMPRESSED == 0 {
			size, err := io.Copy(w, r)
			if err != nil {
				return err
			}
			sec.FileSize = uint64(size)
			sec.Size = sec.FileSize
			// Make sure it is marked as uncompressed.
			sec.Flags = sec.Flags & ^elf.SHF_COMPRESSED
			return nil
		}

		// The section is already compressed.
		// And we have access to the raw source so we'll just read the header,
		// to make sure the section is not corrupted, or has the supported compression type,
		// and copy the data.

		// Check if the compression header is valid.
		rHdr, err := readCompressionHeaderFromRawSource(fhdr, src, int64(sec.Offset))
		if err != nil {
			return fmt.Errorf("error reading uncompressed size from section %s: %w", sec.Name, err)
		}

		uncompressedSize := sec.Size         // = rHdr.Size
		if uncompressedSize > sec.FileSize { // compressedSize
			// The section is not properly compressed.
			// Just copy the data as is.
			compressedSize, err := io.Copy(w, io.NewSectionReader(src, int64(sec.Offset), int64(sec.FileSize)))
			if err != nil {
				return err
			}

			sec.FileSize = uint64(compressedSize)
			sec.Size = uint64(uncompressedSize)
			// Make sure it is marked as compressed.
			sec.Flags = sec.Flags | elf.SHF_COMPRESSED
			return nil
		}

		// compressedSize >= uncompressedSize
		// The section is not properly compressed.
		// We will recompressed it.
		buf := flexbuf.New()
		defer buf.Close()

		rHdr.Type = uint32(elf.COMPRESS_ZLIB)
		headerWritten, err := rHdr.WriteTo(buf)
		if err != nil {
			return err
		}

		offset := buf.Offset()
		if headerWritten != offset {
			return fmt.Errorf("header size %d does not match written size %d", headerWritten, offset)
		}

		// sec.Flags = sec.Flags & ^elf.SHF_COMPRESSED
		// sr := sec.Open()
		// sr := io.NewSectionReader(src, int64(sec.Offset)+int64(rHdr.headerSize), int64(sec.FileSize)-int64(rHdr.headerSize))
		sr := io.NewSectionReader(src, int64(sec.Offset), int64(sec.FileSize))
		compressedSize, uncompressedSize, err := copyCompressed(buf, sr)
		if err != nil {
			return err
		}

		_ = buf.SeekStart()
		written, err := buf.WriteTo(w)
		if err != nil {
			return err
		}

		totalWritten := compressedSize + uint64(headerWritten)
		if totalWritten != uint64(written) {
			return fmt.Errorf("compressed size %d does not match written size %d", totalWritten, written)
		}

		sec.FileSize = totalWritten
		sec.Size = uint64(uncompressedSize) // + uint64(headerWritten)
		return nil
	}
}

type compressionHeader struct {
	byteOrder  binary.ByteOrder
	class      elf.Class
	headerSize int

	Type      uint32
	Size      uint64
	Addralign uint64
}

func (hdr compressionHeader) WriteTo(w io.Writer) (written int, err error) {
	switch hdr.class {
	case elf.ELFCLASS32:
		ch := new(elf.Chdr32)
		ch.Type = uint32(elf.COMPRESS_ZLIB)
		ch.Size = uint32(hdr.Size)
		ch.Addralign = uint32(hdr.Addralign)
		err = binary.Write(w, hdr.byteOrder, ch)
		if err != nil {
			return 0, err
		}
		written = binary.Size(ch)
	case elf.ELFCLASS64:
		ch := new(elf.Chdr64)
		ch.Type = uint32(elf.COMPRESS_ZLIB)
		ch.Size = hdr.Size
		ch.Addralign = hdr.Addralign
		err = binary.Write(w, hdr.byteOrder, ch)
		if err != nil {
			return 0, err
		}
		written = binary.Size(ch)
	case elf.ELFCLASSNONE:
		fallthrough
	default:
		return 0, fmt.Errorf("unknown ELF class: %v", hdr.class)
	}

	return written, nil
}

func readCompressionHeaderFromRawSource(fhdr *elf.FileHeader, src io.ReaderAt, sectionOffset int64) (*compressionHeader, error) {
	hdr := &compressionHeader{}

	switch fhdr.Class {
	case elf.ELFCLASS32:
		ch := new(elf.Chdr32)
		hdr.headerSize = binary.Size(ch)
		sr := io.NewSectionReader(src, sectionOffset, int64(hdr.headerSize))
		if err := binary.Read(sr, fhdr.ByteOrder, ch); err != nil {
			return nil, err
		}
		hdr.class = elf.ELFCLASS32
		hdr.Type = uint32(ch.Type)
		hdr.Size = uint64(ch.Size)
		hdr.Addralign = uint64(ch.Addralign)
		hdr.byteOrder = fhdr.ByteOrder
	case elf.ELFCLASS64:
		ch := new(elf.Chdr64)
		hdr.headerSize = binary.Size(ch)
		sr := io.NewSectionReader(src, sectionOffset, int64(hdr.headerSize))
		if err := binary.Read(sr, fhdr.ByteOrder, ch); err != nil {
			return nil, err
		}
		hdr.class = elf.ELFCLASS64
		hdr.Type = uint32(ch.Type)
		hdr.Size = ch.Size
		hdr.Addralign = ch.Addralign
		hdr.byteOrder = fhdr.ByteOrder
	case elf.ELFCLASSNONE:
		fallthrough
	default:
		return nil, fmt.Errorf("unknown ELF class: %v", fhdr.Class)
	}

	if elf.CompressionType(hdr.Type) != elf.COMPRESS_ZLIB {
		// TODO(kakkoyun): COMPRESS_ZSTD
		// https://github.com/golang/go/issues/55107
		return nil, errors.New("section should be zlib compressed, we are reading from the wrong offset or debug data is corrupt")
	}

	return hdr, nil
}
