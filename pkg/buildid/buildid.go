// Copyright 2022 The Parca Authors
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

	gobuildid "github.com/parca-dev/parca-agent/internal/go/buildid"
	"github.com/parca-dev/parca-agent/internal/pprof/elfexec"
	"github.com/parca-dev/parca-agent/pkg/elfreader"
)

func BuildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open elf: %w", err)
	}
	defer f.Close()

	hasGoBuildIDSection := false
	for _, s := range f.Sections {
		if s.Name == ".note.go.buildid" {
			hasGoBuildIDSection = true
		}
	}

	if hasGoBuildIDSection {
		if id, err := fastGoBuildID(f); err == nil && len(id) > 0 {
			return hex.EncodeToString(id), nil
		}

		id, err := gobuildid.ReadFile(path)
		if err != nil {
			return elfBuildID(f)
		}

		return hex.EncodeToString([]byte(id)), nil
	}

	if id, err := fastGNUBuildID(f); err == nil && len(id) > 0 {
		return hex.EncodeToString(id), nil
	}

	return elfBuildID(f)
}

func fastGoBuildID(f *elf.File) ([]byte, error) {
	findBuildID := func(notes []elfreader.ElfNote) ([]byte, error) {
		var buildID []byte
		for _, note := range notes {
			if note.Name == "Go" && note.Type == elfreader.NoteTypeGoBuildID {
				if buildID == nil {
					buildID = note.Desc
				} else {
					return nil, fmt.Errorf("multiple build ids found, don't know which to use")
				}
			}
		}
		return buildID, nil
	}
	data, err := extractNote(f, ".note.go.buildid", findBuildID)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func fastGNUBuildID(f *elf.File) ([]byte, error) {
	findBuildID := func(notes []elfreader.ElfNote) ([]byte, error) {
		var buildID []byte
		for _, note := range notes {
			if note.Name == "GNU" && note.Type == elfreader.NoteTypeGNUBuildID {
				if buildID == nil {
					buildID = note.Desc
				} else {
					return nil, fmt.Errorf("multiple build ids found, don't know which to use")
				}
			}
		}
		return buildID, nil
	}
	data, err := extractNote(f, ".note.gnu.build-id", findBuildID)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func extractNote(f *elf.File, section string, findBuildID func(notes []elfreader.ElfNote) ([]byte, error)) ([]byte, error) {
	s := f.Section(section)
	if s == nil {
		return nil, fmt.Errorf("failed to find %s section", section)
	}

	notes, err := elfreader.ParseNotes(s.Open(), int(s.Addralign), f.ByteOrder)
	if err != nil {
		return nil, err
	}
	if b, err := findBuildID(notes); b != nil || err != nil {
		return b, err
	}

	return nil, fmt.Errorf("failed to find build id")
}

func elfBuildID(f *elf.File) (string, error) {
	b, err := elfexec.GetBuildID(f)
	if err != nil {
		return "", fmt.Errorf("get elf build id: %w", err)
	}

	if b == nil {
		// GNU build ID doesn't exist, so we hash the .text section. This
		// section typically contains the executable code.
		h := xxhash.New()
		text := f.Section(".text")
		if text == nil {
			return "", errors.New("could not find .text section")
		}
		if _, err := io.Copy(h, text.Open()); err != nil {
			return "", fmt.Errorf("hash elf .text section: %w", err)
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	return hex.EncodeToString(b), nil
}
