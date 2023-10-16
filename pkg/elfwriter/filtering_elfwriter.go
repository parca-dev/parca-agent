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
	"fmt"
	"io"
	"strings"
)

// FilteringWriter is a wrapper around Writer that allows to filter out sections,
// and programs from the source. Then write them to underlying io.WriteSeeker.
type FilteringWriter struct {
	Writer
	src io.ReaderAt

	progPredicates          []func(*elf.Prog) bool
	sectionPredicates       []func(*elf.Section) bool
	sectionHeaderPredicates []func(*elf.Section) bool
}

// NewFilteringWriter creates a new Writer using given source.
func NewFilteringWriter(dst io.WriteSeeker, src io.ReaderAt, opts ...Option) (*FilteringWriter, error) {
	f, err := elf.NewFile(src)
	if err != nil {
		return nil, fmt.Errorf("error reading ELF file: %w", err)
	}
	defer f.Close()

	w, err := newWriter(dst, &f.FileHeader, newSectionReaderWithRawSource(&f.FileHeader, src), opts...)
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
				if sec.Type == elf.SHT_NOBITS && isDWARF(sec) {
					// Normally, this shouldn't be a problem or needs to be handled in the reader.
					// However, gostd debug/elf.DWARF throws an error if this happens.
					// e.g. debug_gdb_scripts
					continue
				}
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

func newSectionReaderWithRawSource(fhdr *elf.FileHeader, src io.ReaderAt) sectionReaderProviderFn {
	return func(sec elf.Section) (io.Reader, error) {
		// Opens the header. If it is compressed, it will un-compress it.
		// If compressed, it will skip past the compression header [1] and
		// give a reader to the section itself.
		//
		// - [1] https://github.com/golang/go/blob/cd33b4089caf362203cd749ee1b3680b72a8c502/src/debug/elf/file.go#L132
		r := sec.Open()
		if sec.Type == elf.SHT_NOBITS {
			// We do not want to give an error if the section type set to SHT_NOBITS.
			// No need to modify the section and no need to copy any data.
			return nil, nil
		}

		// elf.Section.Open() returns a reader that already handles the edge cases of
		// compressed sections. e.g. if the flag SHF_COMPRESSED is set incorrectly,
		// it will still try to set comprssion header by reading the first 12 bytes,
		// and return a correct reader.
		// In this case the returned reader offset: sec.Offset + 12, and size: sec.FileSize - 12.
		if !isCompressed(&sec) {
			return r, nil
		}

		// The section is already compressed.
		if strings.HasPrefix(sec.Name, ".zdebug_") {
			// Section is compressed but it won't have compression header.
			// gostd reader can handle this case.
			return r, nil
		}
		
		// It has a compression header.
		// We have access to the raw source so we'll just read the header,
		// to make sure the section is not corrupted, or has the supported compression type,
		// and copy the data.

		// Check if the compression header is valid.
		rHdr, err := NewCompressionHeaderFromSource(fhdr, src, int64(sec.Offset))
		if err != nil {
			return nil, fmt.Errorf("error reading uncompressed size from section %s: %w", sec.Name, err)
		}

		uncompressedSize := rHdr.Size // = sec.Size
		// compressedSize > uncompressedSize
		// ZLIB compression header size is 2 bytes,
		// and additionally it adds 4 bytes for the adler32 checksum,
		// at the end of the compressed data.
		// So if the compressed size is significantly larger than this overhead,
		// section is corrupted or wrong. We should skip.
		if uncompressedSize+2+4 < sec.FileSize {
			// The section is not properly compressed.
			// Do not copy the data.
			sec.Type = elf.SHT_NOBITS
			return nil, nil
		}

		return io.NewSectionReader(src, int64(sec.Offset), int64(sec.FileSize)), nil
	}
}
