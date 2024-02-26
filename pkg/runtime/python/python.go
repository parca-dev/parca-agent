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
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/libc"
)

// Python symbols to look for:
//
//	2.7:`Py_Main`
//	3.2:`Py_Main`
//	3.3:`Py_Main`
//	3.4:`Py_Main`
//	3.5:`Py_Main`
//	3.6:`Py_Main`
//	3.7:`_Py_UnixMain`
//	3.8:`Py_BytesMain`
//	3.9:`Py_BytesMain`
//	3.10:`Py_BytesMain`
//	3.11:`Py_BytesMain`
var pythonExecutableIdentifyingSymbols = [][]byte{
	[]byte("Py_Main"),
	[]byte("_Py_UnixMain"),
	[]byte("Py_BytesMain"),
}

const (
	pythonRuntimeSymbol     = "_PyRuntime"
	pythonThreadStateSymbol = "_PyThreadState_Current"
	pythonInterpreterSymbol = "interp_head"
)

var pythonLibraryIdentifyingSymbols = [][]byte{
	[]byte(pythonRuntimeSymbol),
	[]byte(pythonThreadStateSymbol),
}

var libRegex = regexp.MustCompile(`/libpython\d.\d\d?(m|d|u)?.so`)

func isPythonLib(pathname string) bool {
	// Alternatively, we could check the ELF file for the interpreter symbol.
	return libRegex.MatchString(pathname)
}

func isPythonBin(pathname string) bool {
	return strings.Contains(path.Base(pathname), "python")
}

func IsRuntime(proc procfs.Proc) (bool, error) {
	// First, let's check the executable's pathname since it's the cheapest and fastest.
	exe, err := proc.Executable()
	if err != nil {
		return false, err
	}

	if isPythonBin(exe) {
		// Let's make sure it's a python process by checking the ELF file.
		ef, err := elf.Open(absolutePath(proc, exe))
		if err != nil {
			return false, fmt.Errorf("open elf file: %w", err)
		}

		return runtime.HasSymbols(ef, pythonExecutableIdentifyingSymbols)
	}

	// If the executable is not a Python interpreter, let's check the memory mappings.
	maps, err := proc.ProcMaps()
	if err != nil {
		return false, fmt.Errorf("error reading process maps: %w", err)
	}
	for _, mapping := range maps {
		if isPythonLib(mapping.Pathname) {
			// Let's make sure it's a Python process by checking the ELF file.
			ef, err := elf.Open(absolutePath(proc, mapping.Pathname))
			if err != nil {
				return false, fmt.Errorf("open elf file: %w", err)
			}

			return runtime.HasSymbols(ef, pythonLibraryIdentifyingSymbols)
		}
	}

	return false, nil
}

func RuntimeInfo(proc procfs.Proc) (*runtime.Runtime, error) {
	isPython, err := IsRuntime(proc)
	if err != nil {
		return nil, fmt.Errorf("is runtime: %w", err)
	}
	if !isPython {
		return nil, nil //nolint:nilnil
	}

	rt := &runtime.Runtime{
		Name: "python",
	}

	interpreter, err := newInterpreter(proc)
	if err != nil {
		return nil, fmt.Errorf("new interpreter: %w", err)
	}
	rt.Version = interpreter.version.String()
	return rt, nil
}

func InterpreterInfo(proc procfs.Proc) (*runtime.Interpreter, error) {
	interpreter, err := newInterpreter(proc)
	if err != nil {
		return nil, fmt.Errorf("new interpreter: %w", err)
	}
	defer interpreter.Close()

	threadStateAddress, err := interpreter.threadStateAddress()
	if err != nil {
		return nil, fmt.Errorf("python version: %s, thread state address: %w", interpreter.version.String(), err)
	}

	var tlsKey uint64
	if threadStateAddress == 0 {
		tlsKey, err = interpreter.tlsKey()
		if err != nil {
			return nil, fmt.Errorf("python version: %s, tls key: %w", interpreter.version.String(), err)
		}
	}

	interpreterAddress, err := interpreter.interpreterAddress()
	if err != nil {
		return nil, fmt.Errorf("python version: %s, interpreter address: %w", interpreter.version.String(), err)
	}
	if interpreterAddress == 0 {
		return nil, fmt.Errorf("invalid address, python version: %s, interpreter address: 0x%016x", interpreter.version.String(), interpreterAddress)
	}

	libcInfo, err := libc.NewLibcInfo(proc)
	if err != nil {
		above312, err := semver.NewConstraint(">=3.12.0-0")
		if err != nil {
			return nil, fmt.Errorf("python version: %s, libc info: %w", interpreter.version.String(), err)
		}
		if above312.Check(interpreter.version) {
			// It's only critical to have the libc info for Python 3.12 and above.
			return nil, fmt.Errorf("python version: %s, libc info: %w", interpreter.version.String(), err)
		}
	}

	return &runtime.Interpreter{
		Runtime: runtime.Runtime{
			Name:    "Python",
			Version: interpreter.version.String(),
		},
		Type:               runtime.InterpreterPython,
		InterpreterAddress: interpreterAddress,
		LibcInfo:           libcInfo,
		MainThreadAddress:  threadStateAddress,
		TLSKey:             tlsKey,
	}, nil
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}
