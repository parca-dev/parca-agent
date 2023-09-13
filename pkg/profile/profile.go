// Copyright 2023 The Parca Authors
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

package profile

import "io"

type PID uint32

type ProcessRawData struct {
	PID        PID
	RawSamples []RawSample
}

type RawSample struct {
	TID         PID
	UserStack   []uint64
	KernelStack []uint64
	// The interpreter stack is formed of the ids we need to fetch
	// from the corresponding BPF map in order to fetch the interpreter
	// frame.
	InterpreterStack []uint64
	Value            uint64
}

type RawData []ProcessRawData

type Function struct {
	ModuleName string
	Name       string
	Filename   string
	StartLine  int
}

func (f Function) FullName() string {
	if f.ModuleName == "" {
		return f.Name
	}
	return f.ModuleName + "::" + f.Name
}

type Writer interface {
	Write(io.Writer) error
	WriteUncompressed(io.Writer) error
}
