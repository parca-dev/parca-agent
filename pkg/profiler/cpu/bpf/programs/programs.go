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

package bpfprograms

import (
	"embed"
	"fmt"
	"io"
	"runtime"
)

const (
	StackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in BPF program.
	tripleStackDepth = StackDepth * 3
)

var (
	//go:embed objects/*
	objects embed.FS

	// native programs.
	CPUProgramFD              = uint64(0)
	RubyEntrypointProgramFD   = uint64(1)
	PythonEntrypointProgramFD = uint64(2)
	// rbperf programs.
	RubyUnwinderProgramFD = uint64(0)
	// python programs.
	PythonUnwinderProgramFD = uint64(0)

	ProgramName              = "profile_cpu"
	DWARFUnwinderProgramName = "walk_user_stacktrace_impl"
)

type CombinedStack [tripleStackDepth]uint64

func OpenNative() ([]byte, error) {
	return open(fmt.Sprintf("objects/%s/cpu.bpf.o", runtime.GOARCH))
}

func OpenRuby() ([]byte, error) {
	return open(fmt.Sprintf("objects/%s/rbperf.bpf.o", runtime.GOARCH))
}

func OpenPython() ([]byte, error) {
	return open(fmt.Sprintf("objects/%s/pyperf.bpf.o", runtime.GOARCH))
}

func open(file string) ([]byte, error) {
	f, err := objects.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open BPF object: %w", err)
	}

	// Note: no need to close this file, it's a virtual file from embed.FS, for
	// which Close is a no-op.

	bpfObj, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read BPF object: %w", err)
	}

	return bpfObj, nil
}
