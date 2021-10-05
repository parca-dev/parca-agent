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
	"crypto/sha1"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/parca-dev/parca-agent/pkg/byteorder"
	gobuildid "github.com/parca-dev/parca-agent/pkg/internal/go/buildid"
	"github.com/parca-dev/parca-agent/pkg/internal/pprof/elfexec"
)

func KernelBuildID() (string, error) {
	f, err := os.Open("/sys/kernel/notes")
	if err != nil {
		return "", err
	}

	notes, err := elfexec.ParseNotes(f, 4, byteorder.GetHostByteOrder())
	if err != nil {
		return "", err
	}

	for _, n := range notes {
		if n.Name == "GNU" {
			return fmt.Sprintf("%x", n.Desc), nil
		}
	}

	return "", errors.New("kernel build id not found")
}

func BuildID(path string) (string, error) {
	exe, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open elf: %w", err)
	}

	hasBuildIDSection := false
	for _, s := range exe.Sections {
		if s.Name == ".note.go.buildid" {
			hasBuildIDSection = true
		}
	}

	if hasBuildIDSection {
		exe.Close()

		id, err := gobuildid.ReadFile(path)
		if err != nil {
			return elfBuildID(path)
		}

		return hex.EncodeToString([]byte(id)), nil
	}
	exe.Close()

	return elfBuildID(path)
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

		h := sha1.New()
		if _, err := io.Copy(h, ef.Section(".text").Open()); err != nil {
			return "", fmt.Errorf("hash elf .text section: %w", err)
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	return hex.EncodeToString(b), nil
}
