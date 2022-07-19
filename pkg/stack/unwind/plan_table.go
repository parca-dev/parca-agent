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

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	"github.com/google/pprof/profile"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"

	"github.com/parca-dev/parca-agent/pkg/buildid"
)

type MappingCache interface {
	MappingForPID(pid int) ([]*profile.Mapping, error)
}

// TODO(kakkoyun): Can we speed parsin using or look up using .eh_frame_hdr?
type PlanTableBuilder struct {
	logger       log.Logger
	mappingCache MappingCache
	fdeCache     cache.Cache
}

// TODO(kakkoyun): A better type?
type Op uint8

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

func (i Instruction) Bytes(order binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	data := []interface{}{
		uint8(i.Op),
		i.Reg,
		i.Off,
	}
	for _, v := range data {
		if err := binary.Write(buf, order, v); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type PlanTableRow struct {
	Begin, End uint64
	RIP, RSP   Instruction
}

type PlanTable []PlanTableRow

func (t PlanTable) Len() int           { return len(t) }
func (t PlanTable) Less(i, j int) bool { return t[i].Begin < t[j].Begin }
func (t PlanTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

func NewPlanTableBuilder(logger log.Logger, mappingCache MappingCache) *PlanTableBuilder {
	return &PlanTableBuilder{logger: logger, mappingCache: mappingCache, fdeCache: cache.New(cache.WithMaximumSize(128))}
}

func (ptb *PlanTableBuilder) PlanTableForPid(pid int) (PlanTable, error) {
	level.Warn(ptb.logger).Log("msg", "unwind.PlanTableForPid", "pid", pid)
	mappings, err := ptb.mappingCache.MappingForPID(pid)
	if err != nil {
		return nil, err
	}

	if len(mappings) == 0 {
		return nil, fmt.Errorf("no mapping found for pid %d", pid)
	}

	res := []PlanTable{}
	for _, m := range mappings {
		if m.BuildID == "" || m.File == "[vdso]" || m.File == "[vsyscall]" {
			continue
		}

		abs := path.Join(fmt.Sprintf("/proc/%d/root", pid), m.File)
		fdes, err := ptb.readFDEs(abs, m.Start)
		if err != nil {
			level.Warn(ptb.logger).Log("msg", "failed to read frame description entries", "obj", abs, "err", err)
			continue
		}

		res = append(res, buildTable(fdes))
	}

	// TODO(kakkoyun): Merge and order instructions of PlanTables.
	// TODO(kakkoyun): Figure out mapping start address usage.
	return res[0], nil
}

func (ptb *PlanTableBuilder) readFDEs(path string, start uint64) (frame.FrameDescriptionEntries, error) {
	buildID, err := buildid.BuildID(path)
	if err != nil {
		return nil, err
	}

	if fde, ok := ptb.fdeCache.GetIfPresent(buildID); ok {
		v, ok := fde.(frame.FrameDescriptionEntries)
		if !ok {
			return nil, fmt.Errorf("invalid type of cached FDEs")
		}
		return v, nil
	}

	obj, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open elf: %w", err)
	}
	defer obj.Close()

	sec := obj.Section(".eh_frame")
	if sec == nil {
		return nil, fmt.Errorf("failed to find .eh_frame section")
	}

	// TODO(kakkoyun): Consider using the debug_frame section as a fallback.
	// unwind, err := obj.Section(".debug_frame").Data()

	ehFrame, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .eh_frame section: %w", err)
	}

	// TODO(kakkoyun): byte order of a DWARF section can be different.
	// TODO(kakkoyun): Needs to support DWARF64 as well.

	// TODO(kakkoyun): Is static base correct?
	fde, err := frame.Parse(ehFrame, obj.ByteOrder, start, pointerSize(obj.Machine), sec.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame data: %w", err)
	}

	ptb.fdeCache.Put(buildID, fde)
	return fde, nil
}

func buildTable(fdes frame.FrameDescriptionEntries) PlanTable {
	table := make(PlanTable, 0, len(fdes))
	for _, fde := range fdes {
		table = append(table, buildTableRow(fde))
	}
	// TODO(kakkayun): Print table and debug.
	// Comparison with readelf -wF and llvm-dwarfdump --eh-frame.

	// Using tests!
	return table
}

func buildTableRow(fde *frame.DescriptionEntry) PlanTableRow {
	// TODO(kakkoyun): Calculate relative address for the process?
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
		// nolint:exhaustive
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

	// TODO(kakkoyun): Return address? Is it in eBPF?
	row.RSP = Instruction{Op: OpRegister, Reg: fc.CFA.Reg, Off: fc.CFA.Offset}
	return row
}

func pointerSize(arch elf.Machine) int {
	//nolint:exhaustive
	switch arch {
	case elf.EM_386:
		return 4
	case elf.EM_AARCH64, elf.EM_X86_64:
		return 8
	default:
		return 0
	}
}
