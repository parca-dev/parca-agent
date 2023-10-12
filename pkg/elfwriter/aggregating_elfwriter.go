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
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
)

// AggregatingWriter is a wrapper around Writer that aggregates all given the sections,
// and programs. Then write them to underlying io.WriteSeeker.
type AggregatingWriter struct {
	Writer
}

// NewAggregatingWriter creates a new Aggregating using given header.
func NewAggregatingWriter(dst io.WriteSeeker, header *elf.FileHeader, opts ...Option) (*AggregatingWriter, error) {
	w, err := newWriter(dst, header, newSectionWriterWithoutRawSource(header), opts...)
	if err != nil {
		return nil, err
	}
	return &AggregatingWriter{*w}, nil
}

// AddPrograms adds programs to the buffer.
func (w *AggregatingWriter) AddPrograms(progs ...*elf.Prog) {
	w.progs = append(w.progs, progs...)
}

// AddSections add sections to the buffer.
// If sections have links to other sections, the order of the given sections is important.
func (w *AggregatingWriter) AddSections(secs ...*elf.Section) {
	w.sections = append(w.sections, secs...)

	srcTgt := make(map[string]string)
	for _, sec := range w.sections {
		if sec.Link != 0 {
			srcTgt[sec.Name] = w.sections[sec.Link].Name
		}
	}
	w.Writer.sectionLinks = srcTgt
}

// AddHeaderOnlySections add header only sections to the buffer.
func (w *AggregatingWriter) AddHeaderOnlySections(headers ...elf.SectionHeader) {
	w.sectionHeaders = append(w.sectionHeaders, headers...)
}

func newSectionWriterWithoutRawSource(fhdr *elf.FileHeader) sectionWriterFn {
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
			// The section is already compressed, but don't have access to the raw source.
			// We need to un-compress and compress it again.
			switch fhdr.Class {
			case elf.ELFCLASS32:
				ch := new(elf.Chdr32)
				ch.Type = uint32(elf.COMPRESS_ZLIB)
				ch.Addralign = uint32(sec.Addralign)
				ch.Size = uint32(sec.Size)
				buf := bytes.NewBuffer(nil)
				err := binary.Write(buf, fhdr.ByteOrder, ch)
				if err != nil {
					return err
				}
				if _, err := w.Write(buf.Bytes()); err != nil {
					return err
				}
			case elf.ELFCLASS64:
				ch := new(elf.Chdr64)
				ch.Type = uint32(elf.COMPRESS_ZLIB)
				ch.Addralign = sec.Addralign
				ch.Size = sec.Size
				buf := bytes.NewBuffer(nil)
				err := binary.Write(buf, fhdr.ByteOrder, ch)
				if err != nil {
					return err
				}
				if _, err := w.Write(buf.Bytes()); err != nil {
					return err
				}
			case elf.ELFCLASSNONE:
				fallthrough
			default:
				return fmt.Errorf("unknown ELF class: %v", fhdr.Class)
			}

			compressedSize, uncompressedSize, err := copyCompressed(w, r)
			if err != nil {
				return err
			}
			sec.FileSize = compressedSize
			sec.Size = uncompressedSize
		}
		return nil
	}
}
