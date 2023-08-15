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
	"debug/elf"
	"fmt"
)

// IsASLRElegibleElf returns whether the elf executable could be elegible for
// address space layout randomization (ASLR).
//
// Whether to enable ASLR for a process is decided in this kernel code
// path (https://github.com/torvalds/linux/blob/v5.0/fs/binfmt_elf.c#L955).
//
// Note(javierhonduco): This check is a bit simplistic and might not work
// for every case. We might want to check across multiple kernels. It probably
// won't be correct for the dynamic loader itself. See link above.
func IsASLRElegibleElf(elfFile *elf.File) bool {
	return elfFile.FileHeader.Type == elf.ET_DYN
}

func IsASLRElegible(path string) (bool, error) {
	elfFile, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed opening elf file with %w", err)
	}
	defer elfFile.Close()

	return IsASLRElegibleElf(elfFile), nil
}

// FindTextProgHeader finds the program segment header containing the .text
// section or nil if the segment cannot be found.
func FindTextProgHeader(f *elf.File) *elf.ProgHeader {
	for _, s := range f.Sections {
		if s.Name == ".text" {
			// Find the LOAD segment containing the .text section.
			for _, p := range f.Progs {
				// Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
				// LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x0001ed 0x0001ed R E 0x1000
				if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && s.Addr >= p.Vaddr && s.Addr < p.Vaddr+p.Memsz {
					return &p.ProgHeader
				}
			}
		}
	}
	return nil
}

// ProgramHeadersForMapping returns the program segment headers that overlap
// the runtime mapping with file offset mapOff and memory size mapSz. We skip
// over segments zero file size because their file offset values are unreliable.
// Even if overlapping, a segment is not selected if its aligned file offset is
// greater than the mapping file offset, or if the mapping includes the last
// page of the segment, but not the full segment and the mapping includes
// additional pages after the segment end.
// The function returns a slice of pointers to the headers in the input
// slice, which are valid only while phdrs is not modified or discarded.
func ProgramHeadersForMapping(phdrs []elf.ProgHeader, mapOff, mapSz uint64) []*elf.ProgHeader {
	const (
		// pageSize defines the virtual memory page size used by the loader. This
		// value is dependent on the memory management unit of the CPU. The page
		// size is 4KB virtually on all the architectures that we care about, so we
		// define this metric as a constant. If we encounter architectures where
		// page sie is not 4KB, we must try to guess the page size on the system
		// where the profile was collected, possibly using the architecture
		// specified in the ELF file header.
		pageSize       = 4096
		pageOffsetMask = pageSize - 1
	)
	mapLimit := mapOff + mapSz
	var headers []*elf.ProgHeader
	for i := range phdrs {
		p := &phdrs[i]
		// Skip over segments with zero file size. Their file offsets can have
		// arbitrary values, see b/195427553.
		if p.Filesz == 0 {
			continue
		}
		segLimit := p.Off + p.Memsz
		// The segment must overlap the mapping.
		if p.Type == elf.PT_LOAD && mapOff < segLimit && p.Off < mapLimit {
			// If the mapping offset is strictly less than the page aligned segment
			// offset, then this mapping comes from a different segment, fixes
			// b/179920361.
			alignedSegOffset := uint64(0)
			if p.Off > (p.Vaddr & pageOffsetMask) {
				alignedSegOffset = p.Off - (p.Vaddr & pageOffsetMask)
			}
			if mapOff < alignedSegOffset {
				continue
			}
			// If the mapping starts in the middle of the segment, it covers less than
			// one page of the segment, and it extends at least one page past the
			// segment, then this mapping comes from a different segment.
			if mapOff > p.Off && (segLimit < mapOff+pageSize) && (mapLimit >= segLimit+pageSize) {
				continue
			}
			headers = append(headers, p)
		}
	}
	return headers
}

// HeaderForFileOffset attempts to identify a unique program header that
// includes the given file offset. It returns an error if it cannot identify a
// unique header.
func HeaderForFileOffset(headers []*elf.ProgHeader, fileOffset uint64) (*elf.ProgHeader, error) {
	var ph *elf.ProgHeader
	for _, h := range headers {
		if fileOffset >= h.Off && fileOffset < h.Off+h.Memsz {
			if ph != nil {
				// Assuming no other bugs, this can only happen if we have two or
				// more small program segments that fit on the same page, and a
				// segment other than the last one includes uninitialized data, or
				// if the debug binary used for symbolization is stripped of some
				// sections, so segment file sizes are smaller than memory sizes.
				return nil, fmt.Errorf("found second program header (%#v) that matches file offset %x, first program header is %#v. Is this a stripped binary, or does the first program segment contain uninitialized data?", *h, fileOffset, *ph)
			}
			ph = h
		}
	}
	if ph == nil {
		return nil, fmt.Errorf("no program header matches file offset %x", fileOffset)
	}
	return ph, nil
}
