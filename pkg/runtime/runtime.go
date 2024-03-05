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

type UnwinderType uint64

const (
	UnwinderNone UnwinderType = iota
	UnwinderRuby
	UnwinderPython
	UnwinderJava
)

func (it UnwinderType) String() string {
	switch it {
	case UnwinderNone:
		return "<not an unwinder>"
	case UnwinderRuby:
		return "Ruby"
	case UnwinderPython:
		return "Python"
	case UnwinderJava:
		return "Java"
	default:
		return "<no string found>"
	}
}

type VersionSource string

const (
	VersionSourcePath   VersionSource = "path"
	VersionSourceMemory VersionSource = "memory"
	VersionSourceFile   VersionSource = "file"
)

type RuntimeName string

type Runtime struct {
	Name          RuntimeName
	Version       string
	VersionSource VersionSource
}

type UnwinderInfo interface {
	Type() UnwinderType
	Runtime() Runtime
}
