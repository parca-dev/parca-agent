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
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"

	"github.com/prometheus/procfs"

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

var nodejsVersionRegex = regexp.MustCompile(`v([0-9]+)(\.[0-9]+)(\.[0-9]+)` +
	`(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?` +
	`(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?`)

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

	versionString, err := runtime.ScanRodataForVersion(f, nodejsVersionRegex)
	if err == nil {
		rt.Version = versionString
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

	versionString, err = runtime.ScanRodataForVersion(lf, nodejsVersionRegex)
	if err != nil {
		return rt, fmt.Errorf("version from data: %w", err)
	}

	rt.Version = versionString
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
