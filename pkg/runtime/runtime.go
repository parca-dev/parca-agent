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

package runtime

import "github.com/parca-dev/parca-agent/pkg/runtime/libc"

type InterpreterType uint64

const (
	InterpreterNone InterpreterType = iota
	InterpreterRuby
	InterpreterPython
)

func (it InterpreterType) String() string {
	switch it {
	case InterpreterNone:
		return "<not an interpreter>"
	case InterpreterRuby:
		return "Ruby"
	case InterpreterPython:
		return "Python"
	default:
		return "<no string found>"
	}
}

type VersionSource string

const (
	VersionSourcePath   VersionSource = "path"
	VersionSourceMemory VersionSource = "memory"
)

type RuntimeName string

type Runtime struct {
	Name          RuntimeName
	Version       string
	VersionSource VersionSource
}

type Interpreter struct {
	Runtime
	Type InterpreterType

	LibcInfo *libc.LibcInfo

	// The address of the main thread state for interpreters.
	MainThreadAddress  uint64
	InterpreterAddress uint64
	TLSKey             uint64
}
