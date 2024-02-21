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

package nodejs

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"
	"github.com/xyproto/ainur"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

var nodejsIdentifyingSymbols = [][]byte{
	[]byte("InterpreterEntryTrampoline"),
}

func IsV8(path string) (bool, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("open elf file: %w", err)
	}
	defer ef.Close()

	return runtime.HasSymbols(ef, nodejsIdentifyingSymbols)
}

func IsRuntime(proc procfs.Proc) (bool, error) {
	exe, err := proc.Executable()
	if err != nil {
		return false, err
	}

	var isNodeJS bool
	if isNodeJSBin(exe) {
		var err error
		ef, err := elf.Open(absolutePath(proc, exe))
		if err != nil {
			return false, fmt.Errorf("open elf file: %w", err)
		}

		isNodeJS, err = runtime.HasSymbols(ef, nodejsIdentifyingSymbols)
		if err != nil {
			return false, fmt.Errorf("failed to check for symbols: %w", err)
		}
	}

	if isNodeJS {
		return true, nil
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return false, fmt.Errorf("error reading process maps: %w", err)
	}

	var (
		found bool
		lib   string
	)
	for _, m := range maps {
		if pathname := m.Pathname; pathname != "" {
			if m.Perms.Execute {
				if isNodeJSLib(pathname) {
					found = true
					lib = pathname
					break
				}
			}
		}
	}
	if !found {
		// If we didn't find a library, we can't be sure that this is a nodejs process.
		return false, nil
	}

	ef, err := elf.Open(absolutePath(proc, lib))
	if err != nil {
		return false, fmt.Errorf("open elf file: %w", err)
	}

	isNodeJS, err = runtime.HasSymbols(ef, nodejsIdentifyingSymbols)
	if err != nil {
		return false, fmt.Errorf("failed to check for symbols: %w", err)
	}

	return isNodeJS, nil
}

func RuntimeInfo(proc procfs.Proc) (*runtime.Runtime, error) {
	isNodeJS, err := IsRuntime(proc)
	if err != nil {
		return nil, fmt.Errorf("is runtime: %w", err)
	}
	if !isNodeJS {
		return nil, nil //nolint:nilnil
	}

	rt := &runtime.Runtime{
		Name: "nodejs",
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

	versionString, err := versionFromData(f)
	if err == nil {
		version, err := semver.NewVersion(versionString)
		if err != nil {
			return rt, fmt.Errorf("new version: %q: %w", versionString, err)
		}
		rt.Version = version.String()
		return rt, nil
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("error reading process maps: %w", err)
	}

	var (
		found bool
		lib   string
	)
	for _, m := range maps {
		if pathname := m.Pathname; pathname != "" {
			if m.Perms.Execute {
				if isNodeJSLib(pathname) {
					found = true
					lib = pathname
					break
				}
			}
		}
	}
	if !found {
		return rt, fmt.Errorf("library %q not found in process maps", exe)
	}

	lf, err := os.Open(absolutePath(proc, lib))
	if err != nil {
		return rt, fmt.Errorf("open library: %w", err)
	}
	defer lf.Close()

	versionString, err = versionFromData(lf)
	if err != nil {
		return rt, fmt.Errorf("version from data: %w", err)
	}

	version, err := semver.NewVersion(versionString)
	if err != nil {
		return rt, fmt.Errorf("new version: %q: %w", versionString, err)
	}
	rt.Version = version.String()
	return rt, nil
}

func isNodeJSBin(exe string) bool {
	return path.Base(exe) == "node" || path.Base(exe) == "nodemon" || path.Base(exe) == "nodejs"
}

var libRegex = regexp.MustCompile(`/libnode.so\.[0-9]+`)

func isNodeJSLib(lib string) bool {
	return libRegex.MatchString(lib)
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}

func versionFromData(f *os.File) (string, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("new file: %w", err)
	}
	defer ef.Close()

	var lastError error
	for _, sec := range ef.Sections {
		if sec.Name == ".data" || sec.Name == ".rodata" {
			versionString, err := scanVersionBytes(sec.Open())
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

const semVerRegex string = `v([0-9]+)(\.[0-9]+)(\.[0-9]+)` +
	`(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?` +
	`(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?`

func scanVersionBytes(r io.ReadSeeker) (string, error) {
	nodejsVersionRegex := regexp.MustCompile(semVerRegex)

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

		matches := nodejsVersionRegex.FindSubmatchIndex(b)
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
			ver, err := semver.NewVersion(string(matched))
			if err != nil {
				return "", fmt.Errorf("failed to create new version, %s: %w", string(matched), err)
			}

			return ver.Original(), nil
		}
	}

	return "", errors.New("version not found")
}
