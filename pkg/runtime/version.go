// Copyright 2022-2024 The Parca Authors
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

package runtime

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/Masterminds/semver/v3"
	"github.com/xyproto/ainur"
)

func ScanRodataForVersion(r io.ReaderAt, rgx *regexp.Regexp) (string, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return "", fmt.Errorf("new file: %w", err)
	}
	defer ef.Close()

	var lastError error
	for _, sec := range ef.Sections {
		if sec.Name == ".data" || sec.Name == ".rodata" {
			versionString, err := scanVersionBytes(sec.Open(), rgx)
			if err != nil {
				lastError = fmt.Errorf("scan version bytes: %w", err)
				continue
			}
			return versionString, nil
		}
	}
	// If it is found, execution should never reach here.
	if lastError != nil {
		return "", lastError
	}
	return "", errors.New("version not found")
}

func ScanReaderForVersion(r io.ReadSeeker, rgx *regexp.Regexp) (string, error) {
	versionString, err := scanVersionBytes(r, rgx)
	if err != nil {
		return "", fmt.Errorf("scan version bytes: %w", err)
	}
	return versionString, nil
}

func scanProcessBSSForVersion(pid int, f *os.File, loadBase uint64, rgx *regexp.Regexp) (string, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("new file: %w", err)
	}
	defer ef.Close()

	for _, sec := range ef.Sections {
		if sec.Name == ".bss" || sec.Type == elf.SHT_NOBITS {
			if sec.Size == 0 {
				continue
			}
			data := make([]byte, sec.Size)
			if err := CopyFromProcessMemory(pid, uintptr(loadBase+sec.Offset), data); err != nil {
				return "", fmt.Errorf("copy address: %w", err)
			}
			r := bytes.NewReader(data)
			versionString, err := scanVersionBytes(r, rgx)
			if err != nil {
				return "", fmt.Errorf("scan version bytes: %w", err)
			}
			return versionString, nil
		}
	}
	return "", errors.New("version not found")
}

func scanVersionBytes(r io.ReadSeeker, rgx *regexp.Regexp) (string, error) {
	bufferSize := 4096
	sr, err := ainur.NewStreamReader(r, bufferSize)
	if err != nil {
		return "", fmt.Errorf("failed to create stream reader: %w", err)
	}

	for {
		b, err := sr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", fmt.Errorf("failed to read next: %w", err)
		}

		matches := rgx.FindSubmatchIndex(b)
		if matches == nil {
			continue
		}

		for i := 0; i < len(matches); i++ {
			if matches[i] == -1 {
				continue
			}

			if _, err := r.Seek(int64(matches[i]), io.SeekStart); err != nil {
				return "", fmt.Errorf("failed to seek to start: %w", err)
			}

			matched := b[matches[i]:matches[i+1]]
			return versionFromMatch(matched)
		}
	}

	return "", errors.New("version not found")
}

var matcherOnlyDigitsAtTheBeginning = regexp.MustCompile(`^([0-9]+)`)

func versionFromMatch(matched []byte) (string, error) {
	ver, err := semver.NewVersion(string(matched))
	if err == nil && ver != nil && ver.String() != "" {
		return ver.String(), nil
	}

	parts := bytes.Split(matched, []byte("."))
	if len(parts) < 2 {
		return "", fmt.Errorf("failed to extract version from compiler type: %s", matched)
	}
	major := string(parts[0])
	minor := string(parts[1])

	patch := "0"
	matchedPatch := matcherOnlyDigitsAtTheBeginning.FindSubmatch(parts[2])
	if len(matchedPatch) > 0 {
		patch = string(matchedPatch[0])
	}

	ver, err = semver.NewVersion(fmt.Sprintf("%s.%s.%s", major, minor, patch))
	if err != nil {
		return "", fmt.Errorf("failed to parse version from compiler type: %s", matched)
	}
	return ver.String(), nil
}

func ScanPathForVersion(path string, rgx *regexp.Regexp) (string, error) {
	versionString, err := scanVersionPath([]byte(path), rgx)
	if err != nil {
		return "", fmt.Errorf("scan version string: %w", err)
	}
	return versionString, nil
}

func scanVersionPath(data []byte, rgx *regexp.Regexp) (string, error) {
	match := rgx.FindSubmatch(data)
	if match == nil {
		return "", errors.New("failed to find version string")
	}

	ver, err := semver.NewVersion(string(match[0]))
	if err != nil {
		return "", fmt.Errorf("failed to create new version, %s: %w", string(match[0]), err)
	}
	if ver == nil || ver.String() == "" {
		return "", errors.New("failed to create new version")
	}
	return ver.String(), nil
}
