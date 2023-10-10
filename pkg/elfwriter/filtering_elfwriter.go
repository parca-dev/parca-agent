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
		if sec.Flags&elf.SHF_COMPRESSED == 0 {
			size, err := io.Copy(w, r)
			if err != nil {
				return err
			}
			sec.FileSize = uint64(size)
			sec.Size = sec.FileSize
		} else {
			// The section is already compressed.
			// And we have access to the raw source so we'll just read the header,
			// to make sure the section is not corrupted, or has the supported compression type,
			// and copy the data.
			uncompressedSize, err := readUncompressedSizeFromRawSource(fhdr, src, int64(sec.Offset))
			if err != nil {
				return fmt.Errorf("error reading uncompressed size from section %s: %w", sec.Name, err)
			}

			_, err = src.Seek(0, io.SeekStart)
			if err != nil {
				return err
			}

			compressedSize, err := io.Copy(w, io.NewSectionReader(src, int64(sec.Offset), int64(sec.FileSize)))
			if err != nil {
				return err
			}

			sec.FileSize = uint64(compressedSize)
			sec.Size = uint64(uncompressedSize)
		}
		return nil
	}
}

func readUncompressedSizeFromRawSource(fhdr *elf.FileHeader, src SeekReaderAt, sectionOffset int64) (uncompressedSize int64, err error) {
	var compressionType elf.CompressionType

	_, err = src.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}

	switch fhdr.Class {
	case elf.ELFCLASS32:
		ch := new(elf.Chdr32)
		sr := io.NewSectionReader(src, sectionOffset, int64(binary.Size(ch)))
		if err := binary.Read(sr, fhdr.ByteOrder, ch); err != nil {
			return 0, err
		}
		compressionType = elf.CompressionType(ch.Type)
		uncompressedSize = int64(ch.Size)
	case elf.ELFCLASS64:
		ch := new(elf.Chdr64)
		sr := io.NewSectionReader(src, sectionOffset, int64(binary.Size(ch)))
		if err := binary.Read(sr, fhdr.ByteOrder, ch); err != nil {
			return 0, err
		}
		compressionType = elf.CompressionType(ch.Type)
		uncompressedSize = int64(ch.Size)
	case elf.ELFCLASSNONE:
		fallthrough
	default:
		return 0, fmt.Errorf("unknown ELF class: %v", fhdr.Class)
	}

	if compressionType != elf.COMPRESS_ZLIB {
		return 0, errors.New("section should be zlib compressed, we are reading from the wrong offset or debug data is corrupt")
	}

	return uncompressedSize, nil
}
