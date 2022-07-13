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

package elfwriter

import (
	"debug/elf"
	"io"
)

// AggregatingWriter is a wrapper around Writer that aggregates all given the sections,
// and programs. Then write them to underlying io.WriteSeeker.
type AggregatingWriter struct {
	Writer
}

// NewFromHeader creates a new Aggregating using given header.
func NewFromHeader(dst io.WriteSeeker, header *elf.FileHeader, opts ...Option) (*AggregatingWriter, error) {
	w, err := New(dst, header, opts...)
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
