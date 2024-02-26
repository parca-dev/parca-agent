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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	goruntime "runtime"
	"syscall"
	"unsafe"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	runtimedata "github.com/parca-dev/runtime-data/pkg/python"

	"github.com/parca-dev/parca-agent/pkg/elfreader"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

type interpreter struct {
	exe *interpreterExecutableFile
	lib *interpreterExecutableFile

	arch    string
	version *semver.Version
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
		exe *interpreterExecutableFile
		lib *interpreterExecutableFile
	)
	if pythonExecutablePath != "" {
		f, err := os.Open(absolutePath(proc, pythonExecutablePath))
		if err != nil {
			return nil, fmt.Errorf("open executable: %w", err)
		}

		exe, err = newInterpreterExecutableFile(proc.PID, f, pythonExecutableStartAddress)
		if err != nil {
			return nil, fmt.Errorf("new elf file: %w", err)
		}
	}
	if libpythonPath != "" {
		f, err := os.Open(absolutePath(proc, libpythonPath))
		if err != nil {
			return nil, fmt.Errorf("open library: %w", err)
		}

		lib, err = newInterpreterExecutableFile(proc.PID, f, libpythonStartAddress)
		if err != nil {
			return nil, fmt.Errorf("new elf file: %w", err)
		}
	}

	versionSources := []*interpreterExecutableFile{exe, lib}
	var versionString string
	for _, source := range versionSources {
		if source == nil {
			continue
		}

		versionString, err = versionFromBSS(source)
		if versionString != "" && err == nil {
			break
		}
	}

	if versionString == "" {
		for _, source := range versionSources {
			if source == nil {
				continue
			}

			// As a last resort, try to parse the version from the path.
			versionString, err = versionFromPath(source.File)
			if versionString != "" && err == nil {
				break
			}
		}
	}

	version, err := semver.NewVersion(versionString)
	if err != nil {
		return nil, fmt.Errorf("new version: %q: %w", version, err)
	}

	return &interpreter{
		exe:     exe,
		lib:     lib,
		arch:    goruntime.GOARCH,
		version: version,
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
	if err := i.copyMemory(uintptr(tssKeyAddr), tss); err != nil {
		return 0, fmt.Errorf("copy memory: %w", err)
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
	addr, err := i.exe.findAddressOf(s)
	if addr != 0 && err == nil {
		return addr, nil
	}

	if i.lib != nil {
		addr, err = i.lib.findAddressOf(s)
		if addr != 0 && err == nil {
			return addr, nil
		}
	}

	return 0, fmt.Errorf("symbol %q not found", s)
}

func (i interpreter) copyMemory(addr uintptr, buf []byte) error {
	if i.exe != nil {
		if err := i.exe.copyMemory(addr, buf); err != nil {
			return fmt.Errorf("copy memory from exe: %w", err)
		}
	}
	if i.lib != nil {
		if err := i.lib.copyMemory(addr, buf); err != nil {
			return fmt.Errorf("copy memory from lib: %w", err)
		}
	}
	return nil
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

type interpreterExecutableFile struct {
	*os.File
	elfFile *elf.File

	pid   int
	start uint64

	cache map[string]uint64
}

func newInterpreterExecutableFile(pid int, f *os.File, start uint64) (*interpreterExecutableFile, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("new file: %w", err)
	}
	return &interpreterExecutableFile{
		pid:     pid,
		File:    f,
		elfFile: ef,
		start:   start,
		cache:   make(map[string]uint64),
	}, nil
}

func (ef interpreterExecutableFile) offset() uint64 {
	// p_vaddr may be larger than the map address in case when the header has an offset and
	// the map address is relatively small. In this case we can default to 0.
	header := elfreader.FindTextProgHeader(ef.elfFile)
	if header == nil {
		return ef.start
	}
	// return ef.start - header.Vaddr
	return saturatingSub(ef.start, header.Vaddr)
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

type IOVec struct {
	Base *byte
	Len  uint64
}

func (ef interpreterExecutableFile) copyMemory(addr uintptr, buf []byte) error {
	localIOV := IOVec{
		Base: &buf[0],
		Len:  uint64(len(buf)),
	}
	remoteIOV := IOVec{
		Base: (*byte)(unsafe.Pointer(addr)),
		Len:  uint64(len(buf)),
	}

	result, _, errno := syscall.Syscall6(unix.SYS_PROCESS_VM_READV, uintptr(ef.pid),
		uintptr(unsafe.Pointer(&localIOV)), uintptr(1),
		uintptr(unsafe.Pointer(&remoteIOV)), uintptr(1),
		uintptr(0))

	if result == ^uintptr(0) { // -1 in unsigned representation
		//nolint:exhaustive
		switch errno {
		case syscall.ENOSYS, syscall.EPERM:
			procMem, err := os.Open(fmt.Sprintf("/proc/%d/mem", ef.pid))
			if err != nil {
				return err
			}
			defer procMem.Close()

			_, err = procMem.Seek(int64(addr), 0)
			if err != nil {
				return err
			}

			_, err = procMem.Read(buf)
			return err
		default:
			return errno
		}
	}

	return nil
}

func (ef interpreterExecutableFile) findAddressOf(s string) (uint64, error) {
	addr, ok := ef.cache[s]
	if ok {
		return addr, nil
	}
	// Search in both symbol and dynamic symbol tables.
	symbol, err := runtime.FindSymbol(ef.elfFile, s)
	if err != nil {
		return 0, fmt.Errorf("FindSymbol: %w", err)
	}
	// Memoize the result.
	addr = symbol.Value + ef.offset()
	ef.cache[s] = addr
	return addr, nil
}
