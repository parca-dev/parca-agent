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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

type GoVdsoOffsets struct {
	Sp uint32
	Pc uint32
}

type GoLabelsOffsets struct {
	Curg                uint32
	Labels              uint32
	HmapCount           uint32
	HmapLog2BucketCount uint32
	HmapBuckets         uint32
}

type Info struct {
	MOffset       uint32
	VdsoOffsets   GoVdsoOffsets
	LabelsOffsets GoLabelsOffsets

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
	exe = filepath.Join(fmt.Sprintf("/proc/%d/root", proc.PID), exe)
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
	path := filepath.Join(fmt.Sprintf("/proc/%d/root", proc.PID), exe)

	f, err := elf.Open(path)
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

	r.Seek(mType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	curgPType, curgOffset, err := util.ReadChildTypeAndOffset(r, "curg")
	if err != nil {
		return nil, err
	}
	if curgPType.Tag != dwarf.TagPointerType {
		return nil, errors.New("type of curg in m is not a pointer")
	}
	_, err = util.ReadType(r, curgPType)
	if err != nil {
		return nil, err
	}

	_, labelsOffset, err := util.ReadChildTypeAndOffset(r, "labels")
	if err != nil {
		return nil, err
	}

	hmap, err := util.ReadEntry(r, "runtime.hmap", dwarf.TagStructType)
	if err != nil {
		return nil, err
	}

	_, countOffset, err := util.ReadChildTypeAndOffset(r, "count")
	if err != nil {
		return nil, err
	}
	r.Seek(hmap.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, bOffset, err := util.ReadChildTypeAndOffset(r, "B")
	if err != nil {
		return nil, err
	}
	r.Seek(hmap.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, bucketsOffset, err := util.ReadChildTypeAndOffset(r, "buckets")
	if err != nil {
		return nil, err
	}

	compiler, err := cim.Fetch(path)
	if err != nil {
		return nil, err
	}

	return &Info{
		MOffset: uint32(mOffset),
		VdsoOffsets: GoVdsoOffsets{
			Sp: uint32(spOffset),
			Pc: uint32(pcOffset),
		},
		LabelsOffsets: GoLabelsOffsets{
			Curg:                uint32(curgOffset),
			Labels:              uint32(labelsOffset),
			HmapCount:           uint32(countOffset),
			HmapLog2BucketCount: uint32(bOffset),
			HmapBuckets:         uint32(bucketsOffset),
		},
		rt: runtime.Runtime{
			Name:          compiler.Name,
			Version:       compiler.Version,
			VersionSource: runtime.VersionSourceFile,
		},
	}, nil
}
