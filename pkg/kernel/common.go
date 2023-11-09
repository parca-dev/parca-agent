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

package kernel

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

func int8SliceToString(arr []int8) string {
	var b strings.Builder
	for _, v := range arr {
		// NUL byte, as it's a C string.
		if v == 0 {
			break
		}
		b.WriteByte(byte(v))
	}
	return b.String()
}

// Release fetches the version string of the current running kernel.
func Release() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", err
	}

	return int8SliceToString(uname.Release[:]), nil
}

// Machine fetches the machine string of the current running kernel.
func Machine() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", err
	}

	return int8SliceToString(uname.Machine[:]), nil
}

const vdsoPattern = "/usr/lib/modules/*/vdso/*.so"

func FindVDSO() (string, error) {
	matches, err := filepath.Glob(vdsoPattern)
	if err != nil {
		return "", fmt.Errorf("failed to glob %s: %w", vdsoPattern, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no vdso file found")
	}
	return matches[0], nil
}

// unameRelease fetches the version string of the current running kernel.
func unameRelease() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", fmt.Errorf("could not get utsname")
	}

	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}

	ver := string(buf[:])
	ver = strings.Trim(ver, "\x00")

	return ver, nil
}

func parse(s *bufio.Scanner, p map[string]string) error {
	r := regexp.MustCompile("^(?:# *)?(CONFIG_\\w*)(?:=| )(y|n|m|is not set|\\d+|0x.+|\".*\")$")

	for s.Scan() {
		t := s.Text()

		// Skip line if empty.
		if t == "" {
			continue
		}

		// 0 is the match of the entire expression,
		// 1 is the key, 2 is the value.
		m := r.FindStringSubmatch(t)
		if m == nil {
			continue
		}

		if len(m) != 3 {
			return fmt.Errorf("match is not 3 chars long: %v", m)
		}
		// Remove all leading and trailing double quotes from the value.
		if len(m[2]) > 1 {
			m[2] = strings.Trim(m[2], "\"")
		}

		// Insert entry into map.
		p[m[1]] = m[2]
	}

	if err := s.Err(); err != nil {
		return err
	}

	return nil
}
