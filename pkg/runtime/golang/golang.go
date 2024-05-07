// Copyright 2024 The Parca Authors
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

package golang

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"strings"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

type GoVdsoOffsets struct {
	Sp uint32
	Pc uint32
}

type Info struct {
	MOffset     uint32
	VdsoOffsets GoVdsoOffsets

	rt runtime.Runtime
}

func (r *Info) Type() runtime.UnwinderType {
	return runtime.UnwinderGo
}

func (r *Info) Runtime() runtime.Runtime {
	return r.rt
}

func IsRuntime(proc procfs.Proc, cim *runtime.CompilerInfoManager) (bool, error) {
	exe, err := proc.Executable()
	if err != nil {
		return false, err
	}
	compiler, err := cim.Fetch(exe)
	if err != nil {
		return false, err
	}
	isGo := strings.HasPrefix(compiler.Type, "Go")
	return isGo, nil
}

func RuntimeInfo(proc procfs.Proc, cim *runtime.CompilerInfoManager) (*Info, error) {
	exe, err := proc.Executable()
	if err != nil {
		return nil, err
	}

	f, err := elf.Open(exe)
	if err != nil {
		return nil, err
	}

	d, err := f.DWARF()
	if err != nil {
		return nil, err
	}

	r := d.Reader()
	g, err := util.ReadEntry(r, "runtime.g", dwarf.TagStructType)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, errors.New("type runtime.g not found")
	}
	mPType, mOffset, err := util.ReadChildTypeAndOffset(r, "m")
	if err != nil {
		return nil, err
	}
	if mPType.Tag != dwarf.TagPointerType {
		return nil, errors.New("type of m in runtime.g is not a pointer")
	}

	mType, err := util.ReadType(r, mPType)
	if err != nil {
		return nil, err
	}

	_, spOffset, err := util.ReadChildTypeAndOffset(r, "vdsoSP")
	if err != nil {
		return nil, err
	}
	r.Seek(mType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, pcOffset, err := util.ReadChildTypeAndOffset(r, "vdsoPC")
	if err != nil {
		return nil, err
	}
	compiler, err := cim.Fetch(exe)
	if err != nil {
		return nil, err
	}

	return &Info{
		MOffset: uint32(mOffset),
		VdsoOffsets: GoVdsoOffsets{
			Sp: uint32(spOffset),
			Pc: uint32(pcOffset),
		},
		rt: runtime.Runtime{
			Name:          compiler.Name,
			Version:       compiler.Version,
			VersionSource: runtime.VersionSourceFile,
		},
	}, nil
}
