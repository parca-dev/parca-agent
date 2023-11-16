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

package ruby

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

// Ruby symbols to look for:
//
//	1.9:`ruby_init` and `ruby_current_vm`
//	2.0:`ruby_init` and `ruby_current_vm`
//	2.1:`ruby_init`
//	2.2:`ruby_init`
//	2.3:`ruby_init`
//	2.4:`ruby_init`
//	2.5:`ruby_init`
//	2.6:`ruby_init`
//	2.7:`ruby_init`
//	3.0:`ruby_init`
//	3.1:`ruby_init`
//	3.2:`ruby_init`
//	3.3-preview1:`ruby_init`
var rubyExecutableIdentifyingSymbols = [][]byte{
	[]byte("ruby_init"),
}

const (
	// ruby_current_vm_ptr was introduced in Ruby 2.5.
	rubyCurrentVMPtrSymbol = "ruby_current_vm_ptr"
	rubyCurrentVMSymbol    = "ruby_current_vm"
)

var rubyLibraryIdentifyingSymbols = [][]byte{
	[]byte(rubyCurrentVMPtrSymbol),
	[]byte(rubyCurrentVMSymbol),
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}

func IsRuntime(proc procfs.Proc) (bool, error) {
	// First, let's check the executable`pathname since it's the cheapest and fastest.
	exe, err := proc.Executable()
	if err != nil {
		return false, err
	}

	if isRubyBin(exe) {
		// Let's make sure it's a Ruby process by checking the ELF file.
		ef, err := elf.Open(absolutePath(proc, exe))
		if err != nil {
			return false, fmt.Errorf("open elf file: %w", err)
		}

		return runtime.HasSymbols(ef, rubyExecutableIdentifyingSymbols)
	}

	// If the executable is not a Ruby interpreter, let's check the memory mappings.
	maps, err := proc.ProcMaps()
	if err != nil {
		return false, fmt.Errorf("error reading process maps: %w", err)
	}

	for _, mapping := range maps {
		if isRubyLib(mapping.Pathname) {
			// Let's make sure it's a Ruby process by checking the ELF file.
			ef, err := elf.Open(absolutePath(proc, mapping.Pathname))
			if err != nil {
				return false, fmt.Errorf("open elf file: %w", err)
			}

			return runtime.HasSymbols(ef, rubyLibraryIdentifyingSymbols)
		}
	}

	return false, nil
}

// versionFromSymbol reads the Ruby version from the ELF symbol table.
func versionFromSymbol(f *os.File) (string, error) {
	// PERF(javierhonduco): Using Go's ELF reader in the stdlib is very
	// expensive. Do this in a streaming fashion rather than loading everything
	// at once.
	elfFile, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("error opening ELF: %w", err)
	}

	symbols, err := elfFile.Symbols()
	if err != nil {
		return "", fmt.Errorf("error reading ELF symbols: %w", err)
	}
	for _, symbol := range symbols {
		if symbol.Name == "ruby_version" {
			rubyVersionBuf := make([]byte, symbol.Size-1)
			address := symbol.Value

			_, err = f.Seek(int64(address), io.SeekStart)
			if err != nil {
				return "", err
			}

			_, err = f.Read(rubyVersionBuf)
			if err != nil {
				return "", err
			}

			return string(rubyVersionBuf), nil
		}
	}

	return "", errors.New("ruby_version symbol not found")
}

func RuntimeInfo(proc procfs.Proc) (*runtime.Runtime, error) {
	isRuby, err := IsRuntime(proc)
	if err != nil {
		return nil, fmt.Errorf("is runtime: %w", err)
	}
	if !isRuby {
		return nil, nil //nolint:nilnil
	}

	rt := &runtime.Runtime{
		Name: "Ruby",
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

	versionString, err := versionFromSymbol(f)
	if err == nil {
		version, err := semver.NewVersion(versionString)
		if err != nil {
			return rt, fmt.Errorf("new version: %q: %w", versionString, err)
		}
		rt.Version = version
		return rt, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return rt, fmt.Errorf("seek: %w", err)
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
				if isRubyLib(pathname) {
					found = true
					lib = pathname
					break
				}
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("library not found")
	}

	lf, err := os.Open(absolutePath(proc, lib))
	if err != nil {
		return rt, fmt.Errorf("open library: %w", err)
	}

	versionString, err = versionFromSymbol(lf)
	if err == nil {
		version, err := semver.NewVersion(versionString)
		if err != nil {
			return rt, fmt.Errorf("new version: %q: %w", versionString, err)
		}
		rt.Version = version
		return rt, nil
	}

	return rt, nil
}

// InterpreterInfo receives a process pid and memory mappings and
// figures out whether it might be a Ruby interpreter. In that case, it
// returns an `Interpreter` structure with the data that is needed by rbperf
// (https://github.com/javierhonduco/rbperf) to walk Ruby stacks.
func InterpreterInfo(proc procfs.Proc) (*runtime.Interpreter, error) {
	var (
		pid = proc.PID

		rubyBaseAddress    *uint64
		librubyBaseAddress *uint64
		librubyPath        string
	)

	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("error reading process maps: %w", err)
	}

	// Find the load address for the interpreter.
	for _, mapping := range maps {
		if isRubyBin(mapping.Pathname) {
			startAddr := uint64(mapping.StartAddr)
			rubyBaseAddress = &startAddr
			break
		}
	}

	// Find the dynamically loaded libruby, if it exists.
	for _, mapping := range maps {
		if isRubyLib(mapping.Pathname) {
			startAddr := uint64(mapping.StartAddr)
			librubyPath = mapping.Pathname
			librubyBaseAddress = &startAddr
			break
		}
	}

	// If we can't find either, this is most likely not a Ruby
	// process.
	if rubyBaseAddress == nil && librubyBaseAddress == nil {
		return nil, errors.New("does not look like a Ruby Process")
	}

	var rubyExecutable string
	if librubyBaseAddress == nil {
		rubyExecutable = path.Join("/proc/", strconv.Itoa(pid), "/exe")
	} else {
		rubyExecutable = path.Join("/proc/", strconv.Itoa(pid), "/root/", librubyPath)
	}

	// PERF(javierhonduco): Using Go's ELF reader in the stdlib is very
	// expensive. Do this in a streaming fashion rather than loading everything
	// at once.
	elfFile, err := elf.Open(rubyExecutable)
	if err != nil {
		return nil, fmt.Errorf("error opening ELF: %w", err)
	}
	defer elfFile.Close()

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("error reading ELF symbols: %w", err)
	}

	rubyVersion := ""
	for _, symbol := range symbols {
		if symbol.Name == "ruby_version" {
			rubyVersionBuf := make([]byte, symbol.Size-1)
			address := symbol.Value
			f, err := os.Open(rubyExecutable)
			if err != nil {
				return nil, fmt.Errorf("error opening ruby executable: %w", err)
			}

			_, err = f.Seek(int64(address), io.SeekStart)
			if err != nil {
				return nil, err
			}

			_, err = f.Read(rubyVersionBuf)
			if err != nil {
				return nil, err
			}

			rubyVersion = string(rubyVersionBuf)
		}
	}

	if rubyVersion == "" {
		return nil, errors.New("could not find Ruby version")
	}

	splittedVersion := strings.Split(rubyVersion, ".")
	major, err := strconv.Atoi(splittedVersion[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse version: %w", err)
	}
	minor, err := strconv.Atoi(splittedVersion[1])
	if err != nil {
		return nil, fmt.Errorf("could not parse version: %w", err)
	}

	var vmPointerSymbol string
	if major == 2 && minor >= 5 {
		vmPointerSymbol = rubyCurrentVMPtrSymbol
	} else {
		vmPointerSymbol = rubyCurrentVMSymbol
	}

	// We first try to find the symbol in the symbol table, and then in
	// the dynamic symbol table.

	mainThreadAddress := uint64(0)
	for _, symbol := range symbols {
		// TODO(javierhonduco): Using contains is a bit of a hack. Ideally
		// we would like to find out which exact symbol to look for depending
		// on the Ruby version.
		if strings.Contains(symbol.Name, vmPointerSymbol) {
			mainThreadAddress = symbol.Value
		}
	}

	if mainThreadAddress == 0 {
		dynSymbols, err := elfFile.DynamicSymbols()
		if err != nil {
			return nil, fmt.Errorf("error reading dynamic ELF symbols: %w", err)
		}
		for _, symbol := range dynSymbols {
			// TODO(javierhonduco): Same as above.
			if strings.Contains(symbol.Name, vmPointerSymbol) {
				mainThreadAddress = symbol.Value
			}
		}
	}

	if mainThreadAddress == 0 {
		return nil, errors.New("mainThreadAddress should never be zero")
	}

	if librubyBaseAddress == nil {
		mainThreadAddress += *rubyBaseAddress
	} else {
		mainThreadAddress += *librubyBaseAddress
	}

	return &runtime.Interpreter{
		Runtime: runtime.Runtime{
			Name:    "Ruby",
			Version: semver.MustParse(rubyVersion),
		},
		Type:              runtime.InterpreterRuby,
		MainThreadAddress: mainThreadAddress,
	}, nil
}

func isRubyBin(pathname string) bool {
	return strings.Contains(path.Base(pathname), "ruby") || strings.Contains(path.Base(pathname), "irb")
}

func isRubyLib(pathname string) bool {
	// Alternatively, we could check the ELF file for the interpreter symbols.
	return strings.Contains(path.Base(pathname), "libruby")
}
