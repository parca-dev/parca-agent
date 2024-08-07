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

package lua

import (
	"debug/elf"
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
	"golang.org/x/exp/mmap"

	"github.com/parca-dev/parca-agent/pkg/runtime"
)

func IsRuntime(proc procfs.Proc) (bool, error) {
	// flesh out...
	exe, err := proc.Executable()
	if err != nil {
		return false, err
	}
	if strings.HasSuffix(exe, "nginx") {
		return true, nil
	}
	if strings.Contains(exe, "luajit") {
		return true, nil
	}
	if strings.Contains(exe, "howl") {
		return true, nil
	}
	// TODO: what are other popular lua embedders?  We could also just scan mappings for libluajit.so.
	return false, nil
}

type Info struct {
	rt     runtime.Runtime
	rtType runtime.UnwinderType
	// Full path to elf object we'll attach uprobe to, ie /usr/bin/luajit or /usr/lib/libluajit.so.
	Path           string
	PcallOffset    uint
	ResumeOffset   uint
	CurrentLOffset uint
	JITBaseOffset  uint
}

func (i *Info) Type() runtime.UnwinderType {
	return i.rtType
}

func (i *Info) Runtime() runtime.Runtime {
	return i.rt
}

// findOldestParentInFS finds the "root" pid that can access the base
// path, for the host this would be the root pid (ie 1 systemd) for
// docker this would be the docker entrypoint CMD.  Its helpful to
// use the oldest parent in case the process we're trying to profile
// is short lived and attaching uprobes with /proc/<PID>/root paths fails.
func findOldestParentInFS(pid int, base string) (int, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return -1, err
	}
	stat, err := proc.Stat()
	if err != nil {
		return -1, err
	}

	myPath := path.Join("/proc/", strconv.Itoa(pid), "/root/", base)
	parentPath := path.Join("/proc/", strconv.Itoa(stat.PPID), "/root/", base)

	myFileInfo, err := os.Stat(myPath)
	if err != nil {
		return -1, err
	}
	parentFileInfo, err := os.Stat(parentPath)
	if err != nil {
		// If parent cant see that path we're done.
		// nolint: nilerr
		return pid, nil
	}

	mySys, ok := myFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, nil
	}
	parentSys, ok := parentFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, nil
	}

	if mySys.Ino == parentSys.Ino {
		return findOldestParentInFS(stat.PPID, base)
	}
	return pid, nil
}

func findMappingContains(p procfs.Proc, name string) (string, error) {
	maps, err := p.ProcMaps()
	if err != nil {
		return "", err
	}
	for _, m := range maps {
		if strings.Contains(m.Pathname, name) {
			return m.Pathname, nil
		}
	}
	return "", nil
}

func VMInfo(p procfs.Proc) (*Info, error) {
	exe, err := findMappingContains(p, "luajit")
	if err != nil {
		return nil, err
	}
	// No luajit mapping, must be statically linked.
	if exe == "" {
		exe, err = p.Executable()
		if err != nil {
			return nil, err
		}
	}

	pid, err := findOldestParentInFS(p.PID, exe)
	if err != nil {
		return nil, err
	}
	path := path.Join("/proc/", strconv.Itoa(pid), "/root/", exe)

	info := Info{
		rt: runtime.Runtime{
			Name:          "lua",
			Version:       "1.0.0", // TODO: should we test 5.1 and 5.2 or luajit 2.0/2.1?
			VersionSource: "1.0.0",
		},
		rtType: runtime.UnwinderLua,
		Path:   path,
	}

	r, err := mmap.Open(path)
	if err != nil {
		return nil, err
	}

	e, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	sym, err := runtime.FindSymbol(e, "lua_pcall")
	if err != nil {
		return nil, err
	}
	info.PcallOffset = uint(sym.Value)

	sym, err = runtime.FindSymbol(e, "lua_resume")
	if err != nil {
		return nil, err
	}
	info.ResumeOffset = uint(sym.Value)

	if info.PcallOffset == 0 || info.ResumeOffset == 0 {
		return nil, errors.New("unable to locate lua entrypoints for uprobes, lua profiling will be disabled")
	}

	sym, err = runtime.FindSymbol(e, "lua_close")
	if err != nil {
		return nil, err
	}

	b := make([]byte, sym.Size)
	_, err = r.ReadAt(b, int64(sym.Value))
	if err != nil {
		return nil, err
	}

	globalOffset, curLOffset, err := findOffsets(b)
	if err != nil {
		return nil, err
	}

	info.CurrentLOffset = uint(curLOffset)
	// jit_base is always right after cur_L and haven't derived way to pull it from assembly.
	info.JITBaseOffset = info.CurrentLOffset + 8

	if globalOffset != 0x10 {
		return nil, errors.New("unexpected offset for global_State in lua_State")
	}

	return &info, nil
}
