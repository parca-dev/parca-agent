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

package python

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

func versionFromBSS(f *interpreterExecutableFile) (string, error) {
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
			if err := f.copyMemory(uintptr(f.offset()+sec.Offset), data); err != nil {
				return "", fmt.Errorf("copy address: %w", err)
			}
			versionString, err := scanVersionBytes(data)
			if err != nil {
				return "", fmt.Errorf("scan version bytes: %w", err)
			}
			return versionString, nil
		}
	}
	return "", errors.New("version not found")
}

func versionFromPath(f *os.File) (string, error) {
	versionString, err := scanVersionPath([]byte(f.Name()))
	if err != nil {
		return "", fmt.Errorf("scan version string: %w", err)
	}
	return versionString, nil
}

func scanVersionBytes(data []byte) (string, error) {
	re := regexp.MustCompile(`((2|3)\.(3|4|5|6|7|8|9|10|11|12)\.(\d{1,2}))((a|b|c|rc)\d{1,2})?\+? (.{1,64})`)

	match := re.FindSubmatch(data)
	if match == nil {
		return "", errors.New("failed to find version string")
	}

	major, err := strconv.ParseUint(string(match[2]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse major version: %w", err)
	}
	minor, err := strconv.ParseUint(string(match[3]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse minor version: %w", err)
	}
	patch, err := strconv.ParseUint(string(match[4]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse patch version: %w", err)
	}

	release := ""
	if len(match) > 5 && match[5] != nil {
		release = string(match[5])
	}

	return fmt.Sprintf("%d.%d.%d%s", major, minor, patch, release), nil
}

func scanVersionPath(data []byte) (string, error) {
	re := regexp.MustCompile(`python(2|3)\.(\d+)\b`) // python2.x, python3.x

	match := re.FindSubmatch(data)
	if match == nil {
		return "", errors.New("failed to find version string")
	}

	major, err := strconv.ParseUint(string(match[1]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse major version: %w", err)
	}
	minor, err := strconv.ParseUint(string(match[2]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse minor version: %w", err)
	}

	return fmt.Sprintf("%d.%d.0", major, minor), nil
}
