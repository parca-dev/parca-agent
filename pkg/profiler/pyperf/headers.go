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

// nolint: unused
package pyperf

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/parca-dev/parca-agent/pkg/byteorder"
)

type ProcessInfo struct {
	// u64 start_time;
	InterpreterAddr uint64
	ThreadStateAddr uint64
	_padding        [4]byte // Padding for alignment.
	PyVersion       uint32
}

type PyObject struct {
	ObType int64
}

type PyString struct {
	Data int64
	Size int64
}

type PyTypeObject struct {
	TpName int64
}

type PyThreadState struct {
	Next           int64
	Interp         int64
	Frame          int64
	ThreadID       int64
	NativeThreadID int64
	CFrame         int64
}

type PyCFrame struct {
	CurrentFrame int64
}

type PyInterpreterState struct {
	TStateHead int64
}

type PyRuntimeState struct {
	InterpMain int64
}

type PyFrameObject struct {
	FBack       int64
	FCode       int64
	FLineno     int64
	FLocalsplus int64
}

type PyCodeObject struct {
	CoFilename    int64
	CoName        int64
	CoVarnames    int64
	CoFirstlineno int64
}

type PyTupleObject struct {
	ObItem int64
}

type PythonVersionOffsets struct {
	MajorVersion       uint32
	MinorVersion       uint32
	PatchVersion       uint32
	_padding           [4]byte // Padding for alignment.
	PyObject           PyObject
	PyString           PyString
	PyTypeObject       PyTypeObject
	PyThreadState      PyThreadState
	PyCFrame           PyCFrame
	PyInterpreterState PyInterpreterState
	PyRuntimeState     PyRuntimeState
	PyFrameObject      PyFrameObject
	PyCodeObject       PyCodeObject
	PyTupleObject      PyTupleObject
}

func (pvo PythonVersionOffsets) Data() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(int(unsafe.Sizeof(&pvo)))

	if err := binary.Write(buf, byteorder.GetHostByteOrder(), &pvo); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
