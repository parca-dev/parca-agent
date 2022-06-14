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

		id, err := fastGoBuildID(path)
		if err == nil && id != "" {
			return hex.EncodeToString([]byte(id)), nil
		}

		id, err = gobuildid.ReadFile(path)
		if err != nil {
			return elfBuildID(path)
		}

		return hex.EncodeToString([]byte(id)), nil
	}
	f.Close()

	return elfBuildID(path)
}

func fastGoBuildID(path string) (string, error) {
	elfFile, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open elf: %w", err)
	}
	defer elfFile.Close()

	s := elfFile.Section(".note.go.buildid")
	if s == nil {
		return "", fmt.Errorf("failed to find .note.go.buildid section")
	}
	data, err := s.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .note.go.buildid section: %w", err)
	}
	return string(data), nil
}

func elfBuildID(file string) (string, error) {
	f, err := os.Open(file)
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
		f, err = os.Open(file)
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
