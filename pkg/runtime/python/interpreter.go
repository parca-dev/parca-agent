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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	goruntime "runtime"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"

	runtimedata "github.com/parca-dev/runtime-data/pkg/python"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

var (
	versionPathRegex = regexp.MustCompile(`((2|3)\.(3|4|5|6|7|8|9|10|11|12|13)(\.\d{1,2})?)((a|b|c|rc)\d{1,2})?\+?`) // 2.15, 3.12
	versionDataRegex = regexp.MustCompile(`((2|3)\.(3|4|5|6|7|8|9|10|11|12|13)\.(\d{1,2}))((a|b|c|rc)\d{1,2})?\+?`)
)

type interpreter struct {
	pid int
	exe *runtime.ProcessMappedFile
	lib *runtime.ProcessMappedFile

	arch          string
	version       *semver.Version
	versionSource runtime.VersionSource
}

func newInterpreter(proc procfs.Proc) (*interpreter, error) {
	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("error reading process maps: %w", err)
	}

	exePath, err := proc.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable: %w", err)
	}

	isPythonBin := func(pathname string) bool {
		// At this point, we know that we have a python process!
		return pathname == exePath
	}

	var (
		pythonExecutablePath         string
		pythonExecutableStartAddress uint64
		libpythonPath                string
		libpythonStartAddress        uint64
		found                        bool
	)
	for _, m := range maps {
		if pathname := m.Pathname; pathname != "" {
			if m.Perms.Execute {
				if isPythonBin(pathname) {
					pythonExecutablePath = pathname
					pythonExecutableStartAddress = uint64(m.StartAddr)
					found = true
					continue
				}
				if isPythonLib(pathname) {
					libpythonPath = pathname
					libpythonStartAddress = uint64(m.StartAddr)
					found = true
					continue
				}
			}
		}
	}
	if !found {
		return nil, errors.New("not a python process")
	}

	var (
		exe *runtime.ProcessMappedFile
		lib *runtime.ProcessMappedFile
	)
	if pythonExecutablePath != "" {
		f, err := os.Open(absolutePath(proc, pythonExecutablePath))
		if err != nil {
			return nil, fmt.Errorf("open executable: %w", err)
		}

		exe, err = runtime.NewProcessMappedFile(proc.PID, f, pythonExecutableStartAddress)
		if err != nil {
			return nil, fmt.Errorf("new elf file: %w", err)
		}
	}
	if libpythonPath != "" {
		f, err := os.Open(absolutePath(proc, libpythonPath))
		if err != nil {
			return nil, fmt.Errorf("open library: %w", err)
		}

		lib, err = runtime.NewProcessMappedFile(proc.PID, f, libpythonStartAddress)
		if err != nil {
			return nil, fmt.Errorf("new elf file: %w", err)
		}
	}

	var (
		versionSource  runtime.VersionSource
		versionSources = []*runtime.ProcessMappedFile{exe, lib}
	)
	var versionString string
	for _, source := range versionSources {
		if source == nil {
			continue
		}

		versionString, err = source.VersionFromBSS(versionDataRegex)
		if versionString != "" && err == nil {
			versionSource = runtime.VersionSourceMemory
			break
		}
	}

	if versionString == "" {
		for _, source := range versionSources {
			if source == nil {
				continue
			}

			// As a last resort, try to parse the version from the path.
			versionString, err = runtime.ScanPathForVersion(source.File.Name(), versionPathRegex)
			if versionString != "" && err == nil {
				versionSource = runtime.VersionSourcePath
				break
			}
		}
	}
	if versionString == "" {
		return nil, errors.New("version not found")
	}

	version, err := semver.NewVersion(versionString)
	if err != nil {
		return nil, fmt.Errorf("new version: %q: %w", versionString, err)
	}

	return &interpreter{
		pid:           proc.PID,
		exe:           exe,
		lib:           lib,
		arch:          goruntime.GOARCH,
		version:       version,
		versionSource: versionSource,
	}, nil
}

func (i interpreter) threadStateAddress() (uint64, error) {
	const37_11, err := semver.NewConstraint(">=3.7.x-0")
	if err != nil {
		return 0, fmt.Errorf("new constraint: %w", err)
	}

	switch {
	case const37_11.Check(i.version):
		addr, err := i.findAddressOf(pythonRuntimeSymbol) // _PyRuntime
		if err != nil {
			return 0, fmt.Errorf("findAddressOf: %w", err)
		}
		_, initialState, err := runtimedata.GetInitialState(i.version)
		if err != nil {
			return 0, fmt.Errorf("get initial state: %w", err)
		}
		if initialState.ThreadStateCurrent < 0 {
			// This version of Python does not have thread state.
			// We should use TLS for the current thread state.
			return 0, nil
		}
		return addr + uint64(initialState.ThreadStateCurrent), nil
	// Older versions (<3.7.0) of Python do not have the _PyRuntime struct.
	default:
		addr, err := i.findAddressOf(pythonThreadStateSymbol) // _PyThreadState_Current
		if err != nil {
			return 0, fmt.Errorf("findAddressOf: %w", err)
		}
		return addr, nil
	}
}

func (i interpreter) interpreterAddress() (uint64, error) {
	const37_11, err := semver.NewConstraint(">=3.7.x-0")
	if err != nil {
		return 0, fmt.Errorf("new constraint: %w", err)
	}

	switch {
	case const37_11.Check(i.version):
		addr, err := i.findAddressOf(pythonRuntimeSymbol) // _PyRuntime
		if err != nil {
			return 0, fmt.Errorf("findAddressOf: %w", err)
		}
		return addr, nil
	// Older versions (<3.7.0) of Python do not have the _PyRuntime struct.
	default:
		addr, err := i.findAddressOf(pythonInterpreterSymbol) // interp_head
		if err != nil {
			return 0, fmt.Errorf("findAddressOf: %w", err)
		}
		return addr, nil
	}
}

func (i interpreter) tlsKey() (uint64, error) {
	pyRuntimeAddr, err := i.findAddressOf(pythonRuntimeSymbol) // _PyRuntime
	if err != nil {
		return 0, fmt.Errorf("findAddressOf: %w", err)
	}
	_, initialState, err := runtimedata.GetInitialState(i.version)
	if err != nil {
		return 0, fmt.Errorf("get initial state: %w", err)
	}
	tssKeyAddr := pyRuntimeAddr + uint64(initialState.AutoTSSKey)
	tssKeyLayout := initialState.PyTSS

	tss := make([]byte, tssKeyLayout.Size)
	if err := runtime.CopyFromProcessMemory(i.pid, uintptr(tssKeyAddr), tss); err != nil {
		return 0, fmt.Errorf("copy memory from pid (): %w", err)
	}

	// TODO(kakkoyun): offset and size of is_initialized and key should be configurable.
	isInitialized := int32(binary.LittleEndian.Uint32(tss[:tssKeyLayout.Key]))
	key := binary.LittleEndian.Uint32(tss[tssKeyLayout.Key:tssKeyLayout.Size])

	if isInitialized == 0 || int(key) < 0 {
		return 0, errors.New("TLS key is not initialized")
	}
	// TODO(kakkoyun): Use 32-bit key.
	return uint64(key), nil
}

func (i interpreter) findAddressOf(s string) (uint64, error) {
	addr, err := i.exe.FindAddressOf(s)
	if addr != 0 && err == nil {
		return addr, nil
	}

	if i.lib != nil {
		addr, err = i.lib.FindAddressOf(s)
		if addr != 0 && err == nil {
			return addr, nil
		}
	}

	return 0, fmt.Errorf("symbol %q not found", s)
}

func (i interpreter) Close() error {
	if i.exe != nil {
		if err := i.exe.Close(); err != nil {
			return fmt.Errorf("close exe: %w", err)
		}
	}
	if i.lib != nil {
		if err := i.lib.Close(); err != nil {
			return fmt.Errorf("close lib: %w", err)
		}
	}
	return nil
}
