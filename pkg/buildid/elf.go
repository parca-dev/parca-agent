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

package buildid

import (
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/cespare/xxhash/v2"
)

var errNoBuildID = fmt.Errorf("failed to find build id")

func FromELF(ef *elf.File) (string, error) {
	// First, try fast methods.
	hasGoBuildIDSection := false
	for _, s := range ef.Sections {
		if s.Name == ".note.go.buildid" {
			hasGoBuildIDSection = true
		}
	}
	if hasGoBuildIDSection {
		if id, err := fastGo(ef); err == nil && len(id) > 0 {
			return hex.EncodeToString(id), nil
		}
	}
	if id, err := fastGNU(ef); err == nil && len(id) > 0 {
		return hex.EncodeToString(id), nil
	}

	// If that fails, try the slow methods.
	return buildid(ef)
}

// buildid returns the build id for an ELF binary by:
// 1. First, looking for a GNU build-id note.
// 2. If fails, hashing the .text section.
func buildid(ef *elf.File) (string, error) {
	// Search through all the notes for a GNU build ID.
	b, err := slowGNU(ef)
	if err != nil {
		if !errors.Is(err, errNoBuildID) {
			return "", fmt.Errorf("get elf build id: %w", err)
		}
		// If we didn't find a GNU build ID, try hashing the .text section.
	}
	if b != nil {
		return hex.EncodeToString(b), nil
	}

	// Hash the .text section.
	text := ef.Section(".text")
	if text == nil {
		return "", errors.New("could not find .text section")
	}
	h := xxhash.New()
	if _, err := io.Copy(h, text.Open()); err != nil {
		return "", fmt.Errorf("hash elf .text section: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

var findGo = func(notes []elfNote) ([]byte, error) {
	var buildID []byte
	for _, note := range notes {
		if note.Name == "Go" && note.Type == noteTypeGoBuildID {
			if buildID == nil {
				buildID = note.Desc
			} else {
				return nil, fmt.Errorf("multiple build ids found, don't know which to use")
			}
		}
	}
	return buildID, nil
}

// fastGo returns the Go build-ID for an ELF binary by searching specific locations.
func fastGo(f *elf.File) ([]byte, error) {
	data, err := findInNotes(f, ".note.go.buildid", findGo)
	if err != nil {
		return nil, err
	}
	return data, nil
}

var findGNU = func(notes []elfNote) ([]byte, error) {
	var buildID []byte
	for _, note := range notes {
		if note.Name == "GNU" && note.Type == noteTypeGNUBuildID {
			if buildID == nil {
				buildID = note.Desc
			} else {
				return nil, fmt.Errorf("multiple build ids found, don't know which to use")
			}
		}
	}
	return buildID, nil
}

// fastGNU returns the GNU build-ID for an ELF binary by searching specific locations.
func fastGNU(f *elf.File) ([]byte, error) {
	data, err := findInNotes(f, ".note.gnu.build-id", findGNU)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// slowGNU returns the GNU build-ID for an ELF binary by searching through all.
func slowGNU(ef *elf.File) ([]byte, error) {
	for _, p := range ef.Progs {
		if p.Type != elf.PT_NOTE {
			continue
		}
		notes, err := parseNotes(p.Open(), int(p.Align), ef.ByteOrder)
		if err != nil {
			return nil, err
		}
		if b, err := findGNU(notes); b != nil || err != nil {
			return b, err
		}
	}
	for _, s := range ef.Sections {
		if s.Type != elf.SHT_NOTE {
			continue
		}
		notes, err := parseNotes(s.Open(), int(s.Addralign), ef.ByteOrder)
		if err != nil {
			return nil, err
		}
		if b, err := findGNU(notes); b != nil || err != nil {
			return b, err
		}
	}
	return nil, errNoBuildID
}
