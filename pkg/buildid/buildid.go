// Copyright 2021 The Parca Authors
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
	"fmt"
	"io"
	"os"

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

	hasGoBuildIDSection := false
	for _, s := range f.Sections {
		if s.Name == ".note.go.buildid" {
			hasGoBuildIDSection = true
		}
	}

	if hasGoBuildIDSection {
		f.Close()

		if id, err := fastGoBuildID(path); err == nil && len(id) > 0 {
			return hex.EncodeToString(id), nil
		}

		id, err := gobuildid.ReadFile(path)
		if err != nil {
			return elfBuildID(path)
		}

		return hex.EncodeToString([]byte(id)), nil
	}
	f.Close()

	if id, err := fastGNUBuildID(path); err == nil && len(id) > 0 {
		return hex.EncodeToString(id), nil
	}

	return elfBuildID(path)
}

func fastGoBuildID(path string) ([]byte, error) {
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
	data, err := extractNote(path, ".note.go.buildid", findBuildID)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func fastGNUBuildID(path string) ([]byte, error) {
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
	data, err := extractNote(path, ".note.gnu.build-id", findBuildID)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func extractNote(path, section string, findBuildID func(notes []elfreader.ElfNote) ([]byte, error)) ([]byte, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open elf: %w", err)
	}
	defer f.Close()

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

func elfBuildID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}

	b, err := elfexec.GetBuildID(f)
	if err != nil {
		return "", fmt.Errorf("get elf build id: %w", err)
	}

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close elf file binary: %w", err)
	}

	if b == nil {
		f, err = os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open file to read program bytes: %w", err)
		}
		defer f.Close()
		// GNU build ID doesn't exist, so we hash the .text section. This
		// section typically contains the executable code.
		ef, err := elf.NewFile(f)
		if err != nil {
			return "", fmt.Errorf("open file as elf file: %w", err)
		}

		h := xxhash.New()
		if _, err := io.Copy(h, ef.Section(".text").Open()); err != nil {
			return "", fmt.Errorf("hash elf .text section: %w", err)
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	return hex.EncodeToString(b), nil
}
