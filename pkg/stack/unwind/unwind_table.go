// Copyright 2022 The Parca Authors
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
	"debug/elf"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/go-delve/delve/pkg/dwarf/regnum"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

// UnwindTableBuilder helps to build UnwindTable for a given PID.
//
// javierhonduco(note): Caching on PID alone will result in hard to debug issues as
// PIDs are reused. Right now we will parse the CIEs and FDEs over and over. Caching
// will be added later on.
type UnwindTableBuilder struct {
	logger log.Logger
}

func NewUnwindTableBuilder(logger log.Logger) *UnwindTableBuilder {
	return &UnwindTableBuilder{logger: logger}
}

type UnwindTable []UnwindTableRow

func (t UnwindTable) Len() int           { return len(t) }
func (t UnwindTable) Less(i, j int) bool { return t[i].Loc < t[j].Loc }
func (t UnwindTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

// processMaps returns a map of file-backed memory mappings for a given
// process which contains at least one executable section. The value of
// mapping contains the metadata for the first mapping for each file, no
// matter if it's executable or not.
//
// This is needed as typically the first mapped section for a dynamic library
// is not executable, as it may contain only data, such as the `.bss` or the
// `.rodata` section.
func processMaps(pid int) (map[string]*procfs.ProcMap, string, error) {
	p, err := procfs.NewProc(pid)
	if err != nil {
		return nil, "", fmt.Errorf("could not get process: %w", err)
	}
	maps, err := p.ProcMaps()
	if err != nil {
		return nil, "", fmt.Errorf("could not get maps: %w", err)
	}

	// Find the file-backed memory mappings that contain at least one
	// executable section.
	filesWithSomeExecutable := make(map[string]bool)
	for _, map_ := range maps {
		if map_.Pathname != "" && map_.Perms.Execute {
			filesWithSomeExecutable[map_.Pathname] = true
		}
	}

	dynamicExecutables := make(map[string]*procfs.ProcMap)
	mainExecutable := ""

	// Find all the dynamically loaded libraries. We need to make sure
	// that we skip the files that do not have a single executable mapping
	// as these are just data.
	for _, map_ := range maps {
		path := map_.Pathname
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			continue
		}
		// The first entry should be the "main" executable, and not
		// a dynamic library.
		if mainExecutable == "" {
			mainExecutable = map_.Pathname
		}
		_, ok := dynamicExecutables[path]
		if ok {
			continue
		}

		_, ok = filesWithSomeExecutable[path]
		if ok {
			dynamicExecutables[path] = map_
		}
	}

	return dynamicExecutables, mainExecutable, nil
}

func (ptb *UnwindTableBuilder) UnwindTableForPid(pid int) (UnwindTable, error) {
	mappedFiles, mainExec, err := processMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("error opening the maps %w", err)
	}

	ut := UnwindTable{}
	for _, m := range mappedFiles {
		executablePath := path.Join(fmt.Sprintf("/proc/%d/root", pid), m.Pathname)

		level.Info(ptb.logger).Log("msg", "finding tables for mapped executable", "path", executablePath, "starting address", fmt.Sprintf("%x", m.StartAddr))
		fdes, err := ptb.readFDEs(executablePath)
		// TODO(javierhonduco): Add markers in between executable sections.
		if err != nil {
			level.Error(ptb.logger).Log("msg", "failed to read frame description entries", "obj", executablePath, "err", err)
			continue
		}

		rows := buildUnwindTable(fdes)
		level.Info(ptb.logger).Log("msg", "adding tables for mapped executable", "path", executablePath, "rows", len(rows), "low pc", fmt.Sprintf("%x", rows[0].Loc), "high pc", fmt.Sprintf("%x", rows[len(rows)-1].Loc))

		// TODO(javierhonduco): Revisit this logic with PIE executables as it's only correct
		// for non-PIE ones.
		if strings.Contains(executablePath, mainExec) {
			ut = append(ut, rows...)
		} else {
			for i := range rows {
				rows[i].Loc += uint64(m.StartAddr)
			}
			ut = append(ut, rows...)
		}
	}

	// Sort the entries so we can binary search over them.
	sort.Sort(ut)
	return ut, nil
}

func x64RegisterToString(reg uint64) string {
	// TODO(javierhonduco):
	// - add source for this table.
	// - add other architectures.
	x86_64Regs := []string{
		"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15", "rip", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		"xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
		"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "mm0", "mm1", "mm2", "mm3",
		"mm4", "mm5", "mm6", "mm7", "rflags", "es", "cs", "ss", "ds", "fs", "gs",
		"unused1", "unused2", "fs.base", "gs.base", "unused3", "unused4", "tr", "ldtr",
		"mxcsr", "fcw", "fsw",
	}

	return x86_64Regs[reg]
}

// PrintTable is a debugging helper that prints the unwinding table to the given io.Writer.
func (ptb *UnwindTableBuilder) PrintTable(writer io.Writer, path string) error {
	fdes, err := ptb.readFDEs(path)
	if err != nil {
		return err
	}

	for _, fde := range fdes {
		fmt.Fprintf(writer, "=> Function start: %x, Function end: %x\n", fde.Begin(), fde.End())
		tableRows := buildTableRows(fde)
		fmt.Fprintf(writer, "\t(found %d rows)\n", len(tableRows))
		for _, tableRow := range tableRows {
			//nolint:exhaustive
			switch tableRow.CFA.Rule {
			case frame.RuleCFA:
				CFAReg := x64RegisterToString(tableRow.CFA.Reg)
				fmt.Fprintf(writer, "\tLoc: %x CFA: $%s=%-4d", tableRow.Loc, CFAReg, tableRow.CFA.Offset)
			case frame.RuleExpression:
				fmt.Fprintf(writer, "\tLoc: %x CFA: exp     ", tableRow.Loc)
			default:
				return fmt.Errorf("CFA rule is not valid. This should never happen")
			}

			// RuleRegister
			//nolint:exhaustive
			switch tableRow.RBP.Rule {
			case frame.RuleUndefined:
				fmt.Fprintf(writer, "\tRBP: u")
			case frame.RuleRegister:
				RBPReg := x64RegisterToString(tableRow.RBP.Reg)
				fmt.Fprintf(writer, "\tRBP: $%s", RBPReg)
			case frame.RuleOffset:
				fmt.Fprintf(writer, "\tRBP: c%-4d", tableRow.RBP.Offset)
			case frame.RuleExpression:
				fmt.Fprintf(writer, "\tRBP: exp")
			default:
				panic(fmt.Sprintf("Got rule %d for RBP, which wasn't expected", tableRow.RBP.Rule))
			}

			fmt.Fprintf(writer, "\n")
		}
	}

	return nil
}

func (ptb *UnwindTableBuilder) readFDEs(path string) (frame.FrameDescriptionEntries, error) {
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
	// TODO(kakkoyun): Needs to support DWARF64 as well.
	ehFrame, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .eh_frame section: %w", err)
	}

	// TODO(kakkoyun): Byte order of a DWARF section can be different.
	fdes, err := frame.Parse(ehFrame, obj.ByteOrder, 0, pointerSize(obj.Machine), sec.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame data: %w", err)
	}

	return fdes, nil
}

func buildUnwindTable(fdes frame.FrameDescriptionEntries) UnwindTable {
	table := make(UnwindTable, 0, len(fdes))
	for _, fde := range fdes {
		table = append(table, buildTableRows(fde)...)
	}
	return table
}

// UnwindTableRow represents a single row in the unwind table.
// x86_64: rip (instruction pointer register), rsp (stack pointer register), rbp (base pointer/frame pointer register)
// aarch64: lr, sp, fp
type UnwindTableRow struct {
	// The address of the machine instruction.
	// Each row covers a range of machine instruction, from its address (Loc) to that of the row below.
	Loc uint64
	// CFA, the value of the stack pointer in the previous frame.
	CFA frame.DWRule
	// The value of the RBP register.
	RBP frame.DWRule
	// The value of the saved return address. This is not needed in x86_64 as it's part of the ABI but is necessary
	// in arm64.
	RA frame.DWRule
}

func buildTableRows(fde *frame.FrameDescriptionEntry) []UnwindTableRow {
	rows := make([]UnwindTableRow, 0)

	frameContext := frame.ExecuteDwarfProgram(fde)

	instructionContexts := frameContext.InstructionContexts()

	for _, instructionContext := range instructionContexts {
		row := UnwindTableRow{
			Loc: instructionContext.Loc(),
			CFA: instructionContext.CFA,
		}

		// Deal with saved return address.
		rule, found := instructionContext.Regs[instructionContext.RetAddrReg]
		if found {
			row.RA = rule
		} else {
			// The saved return address must be specified.
			panic("no saved return address found")
		}

		// Deal with $rbp.
		rule, found = instructionContext.Regs[regnum.AMD64_Rbp]
		if found {
			row.RBP = rule
		}

		rows = append(rows, row)
	}
	return rows
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
