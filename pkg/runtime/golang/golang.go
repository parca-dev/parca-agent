package golang

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"strings"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/prometheus/procfs"
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
		return nil, fmt.Errorf("type runtime.g not found")
	}
	mPType, mOffset, err := util.ReadChildTypeAndOffset(r, "m")
	if err != nil {
		return nil, err
	}
	if mPType.Tag != dwarf.TagPointerType {
		return nil, fmt.Errorf("type of m in runtime.g is not a pointer")
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
	r.Next()
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
