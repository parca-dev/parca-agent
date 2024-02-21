// Copyright 2023-2024 The Parca Authors
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

package erlang

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
	"github.com/xyproto/ainur"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

var beamIdentifyingSymbols = [][]byte{
	[]byte("erts_schedule"),
}

func IsBEAM(path string) (bool, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("open elf file: %w", err)
	}
	defer ef.Close()

	return runtime.HasSymbols(ef, beamIdentifyingSymbols)
}

func IsRuntime(proc procfs.Proc) (bool, error) {
	exe, err := proc.Executable()
	if err != nil {
		return false, err
	}

	if isBeamBin(exe) {
		isBeam, err := IsBEAM(absolutePath(proc, exe))
		if err != nil {
			return false, fmt.Errorf("is beam: %w", err)
		}

		return isBeam, nil
	}

	return false, nil
}

func RuntimeInfo(proc procfs.Proc) (*runtime.Runtime, error) {
	isBeam, err := IsRuntime(proc)
	if err != nil {
		return nil, fmt.Errorf("is runtime: %w", err)
	}
	if !isBeam {
		return nil, nil //nolint:nilnil
	}

	rt := &runtime.Runtime{
		Name: "erlang",
	}

	exe, err := proc.Executable()
	if err != nil {
		return rt, err
	}

	f, err := os.Open(absolutePath(proc, exe))
	if err != nil {
		return rt, fmt.Errorf("open executable: %w", err)
	}
	defer f.Close()

	versionString, err := versionFromFile(f)
	if err != nil {
		return rt, fmt.Errorf("version from data: %w", err)
	}

	rt.Version = versionString
	return rt, nil
}

func isBeamBin(exe string) bool {
	return path.Base(exe) == "beam.smp"
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}

func versionFromFile(f *os.File) (string, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("new file: %w", err)
	}
	defer ef.Close()

	var lastError error
	for _, sec := range ef.Sections {
		if sec.Name == ".data" {
			// We first find a string with the "Erlang/OTP ", prefix which is
			// followed by the major version number. We then use the major
			// version to find the full version.
			r := sec.Open()
			versionString, err := findBytes(r, versionPrefix, len(versionPrefix)+2)
			if err != nil {
				lastError = fmt.Errorf("scan version bytes: %w", err)
				continue
			}
			versionString = versionString[len(versionPrefix):]

			prefix := make([]byte, len(versionString)+1)
			copy(prefix, versionString)
			prefix[len(prefix)-1] = '.'

			if _, err := r.Seek(0, io.SeekStart); err != nil {
				return "", fmt.Errorf("seek to start: %w", err)
			}

			// Erlang versions are 4 numbers eg. 25.3.2.6 we will be
			// pessimistic and assume that each number is 3 digits delimited by
			// a dot. Since we already have the first number we just need 2
			// dots and 3 numbers.
			fullVersion, err := findBytes(r, prefix, len(prefix)+11)
			if err != nil {
				lastError = fmt.Errorf("scan full version bytes: %w", err)
				continue
			}

			index := strings.IndexByte(fullVersion, 0)
			if index == -1 {
				return "", errors.New("no null byte found")
			}

			return fullVersion[:index], nil
		}
	}
	// If it is found, execution should never reach here.
	if lastError != nil {
		return "", lastError
	}
	return "", errors.New("version not found")
}

var versionPrefix = []byte("Erlang/OTP ")

func findBytes(r io.ReadSeeker, prefix []byte, count int) (string, error) {
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

		index := bytes.Index(b, prefix)
		if index == -1 {
			continue
		}
		// +2 for the version number, at the time of writing Erlang is at 26
		if len(b) < index+count {
			continue
		}

		return string(b[index : index+count]), nil
	}

	return "", errors.New("version not found")
}
