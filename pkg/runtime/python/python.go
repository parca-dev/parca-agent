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
	"path"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"

	runtimedata "github.com/parca-dev/runtime-data/pkg/python"

	"github.com/parca-dev/parca-agent/pkg/elfreader"
	"github.com/parca-dev/parca-agent/pkg/runtime"
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

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
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

type interpreter struct {
	exe *interpreterExecutableFile
	lib *interpreterExecutableFile

	arch    string
	version *semver.Version
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

func (i interpreter) threadStateAddress() (uint64, error) {
	const37_11, err := semver.NewConstraint(">=3.7.x")
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
	const37_11, err := semver.NewConstraint(">=3.7.x")
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
		return addr + uint64(initialState.InterpreterHead), nil
	// Older versions (<3.7.0) of Python do not have the _PyRuntime struct.
	default:
		addr, err := i.findAddressOf(pythonInterpreterSymbol) // interp_head
		if err != nil {
			return 0, fmt.Errorf("findAddressOf: %w", err)
		}
		return addr, nil
	}
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
	if threadStateAddress == 0 {
		return nil, fmt.Errorf("invalid address, python version: %s, thread state address: 0x%016x", interpreter.version.String(), threadStateAddress)
	}

	interpreterAddress, err := interpreter.interpreterAddress()
	if err != nil {
		return nil, fmt.Errorf("python version: %s, interpreter address: %w", interpreter.version.String(), err)
	}
	if interpreterAddress == 0 {
		return nil, fmt.Errorf("invalid address, python version: %s, interpreter address: 0x%016x", interpreter.version.String(), interpreterAddress)
	}

	return &runtime.Interpreter{
		Runtime: runtime.Runtime{
			Name:    "Python",
			Version: interpreter.version.String(),
		},
		Type:               runtime.InterpreterPython,
		MainThreadAddress:  threadStateAddress,
		InterpreterAddress: interpreterAddress,
	}, nil
}

var libRegex = regexp.MustCompile(`/libpython\d.\d\d?(m|d|u)?.so`)

func isPythonLib(pathname string) bool {
	// Alternatively, we could check the ELF file for the interpreter symbol.
	return libRegex.MatchString(pathname)
}

func isPythonBin(pathname string) bool {
	return strings.Contains(path.Base(pathname), "python")
}
