// Copyright (c) 2022 The Parca Authors
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

package unwind

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"path"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"
	
	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/maps"
)

type Unwinder struct {
	logger    log.Logger
	fileCache *maps.PidMappingFileCache
}

type Op uint8 // TODO(kakkoyun): A better type?

// TODO(kakkoyun): Clean up comments.
const (
	// This type of register is not supported.
	OpUnimplemented Op = iota
	// Undefined register. The value will be defined at some later IP in the same DIE.
	OpUndefined
	// Value stored at some offset from `CFA`.
	OpCfaOffset
	// Value of a machine register plus offset.
	OpRegister
)

type Instruction struct {
	Op  Op
	Reg uint64
	Off int64
}

func (i Instruction) Bytes(order binary.ByteOrder) []byte {
	buf := new(bytes.Buffer)
	var data = []interface{}{
		uint8(i.Op),
		i.Reg,
		i.Off,
	}
	for _, v := range data {
		err := binary.Write(buf, order, v)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}
	}
	return buf.Bytes()
}

type PlanTableRow struct {
	Begin, End uint64
	RIP, RSP   Instruction
}

type PlanTable []PlanTableRow

func (t PlanTable) Len() int           { return len(t) }
func (t PlanTable) Less(i, j int) bool { return t[i].Begin < t[j].Begin }
func (t PlanTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

func NewUnwinder(logger log.Logger, fileCache *maps.PidMappingFileCache) *Unwinder {
	return &Unwinder{logger: logger, fileCache: fileCache}
}

func (u *Unwinder) UnwindTableForPid(pid uint32) (map[profile.Mapping]PlanTable, error) {
	level.Warn(u.logger).Log("msg", "unwind.UnwindTableForPid", "pid", pid)
	mappings, err := u.fileCache.MappingForPid(pid)
	if err != nil {
		return nil, err
	}

	if len(mappings) == 0 {
		return nil, fmt.Errorf("no mapping found for pid %d", pid)
	}

	// TODO(kakkoyun): Remove.
	level.Debug(u.logger).Log("msg", "unwind.UnwindTableForPid", "pid", pid, "mappings", len(mappings))
	res := map[profile.Mapping]PlanTable{}
	for _, m := range mappings {
		if m.BuildID == "" || m.File == "[vdso]" || m.File == "[vsyscall]" {
			continue
		}

		// TODO(kakkoyun): Only read the executable.
		abs := path.Join(fmt.Sprintf("/proc/%d/root", pid), m.File)
		fdes, err := readFDEs(abs, m.Start)
		if err != nil {
			level.Warn(u.logger).Log("msg", "failed to read frame description entries", "obj", abs, "err", err)
			continue
		}

		res[*m] = buildTable(fdes)
	}

	return res, nil
}

var fdeCache = map[string]frame.FrameDescriptionEntries{}

func readFDEs(path string, start uint64) (frame.FrameDescriptionEntries, error) {
	buildID, err := buildid.BuildID(path)
	if err != nil {
		return nil, err
	}

	if fde, ok := fdeCache[buildID]; ok {
		return fde, nil
	}

	obj, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open elf: %w", err)
	}
	defer obj.Close()

	// TODO(kakkoyun): Consider using the following section as a fallback.
	// unwind, err := obj.Section(".debug_frame").Data()

	sec := obj.Section(".eh_frame")
	if sec == nil {
		return nil, fmt.Errorf("failed to find .eh_frame section")
	}

	ehFrame, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .eh_frame section: %w", err)
	}

	// TODO(kakkoyun): Cache the unwind plan table.
	// TODO(kakkoyun): Can we assume byte order of ELF file same with .eh_frame? We can, right?!
	fde, err := frame.Parse(ehFrame, obj.ByteOrder, start, pointerSize(obj.Machine), sec.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame data: %w", err)
	}

	fdeCache[buildID] = fde
	return fde, nil
}

func buildTable(fdes frame.FrameDescriptionEntries) PlanTable {
	table := make(PlanTable, 0, len(fdes))
	for _, fde := range fdes {
		table = append(table, buildTableRow(fde))
	}

	return table
}

func buildTableRow(fde *frame.FrameDescriptionEntry) PlanTableRow {
	row := PlanTableRow{
		Begin: fde.Begin(),
		End:   fde.End(),
	}

	fc := frame.ExecuteDwarfProgram(fde)

	// TODO(kakkoyun): Validate.
	// TODO(kakkoyun): Filter noop instructions.

	// RetAddrReg is populated by frame.ExecuteDwarfProgram executeCIEInstructions.
	// TODO(kakkoyun): Is this enough do we need to any arch specific look up?
	// - https://github.com/go-delve/delve/blob/master/pkg/dwarf/regnum
	rule, found := fc.Regs[fc.RetAddrReg]
	if found {
		switch rule.Rule {
		case frame.RuleOffset:
			row.RIP = Instruction{Op: OpCfaOffset, Off: rule.Offset}
		case frame.RuleUndefined:
			row.RIP = Instruction{Op: OpUndefined}
		default:
			row.RIP = Instruction{Op: OpUnimplemented}
		}
	} else {
		row.RIP = Instruction{Op: OpUnimplemented}
	}

	row.RSP = Instruction{Op: OpRegister, Reg: fc.CFA.Reg, Off: fc.CFA.Offset}

	return row
}

func pointerSize(arch elf.Machine) int {
	switch arch {
	case elf.EM_386:
		return 4
	case elf.EM_AARCH64, elf.EM_X86_64:
		return 8
	default:
		return 0
	}
}
