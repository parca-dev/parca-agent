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

//nolint:stylecheck,deadcode,unused
package unwind

import (
	"debug/elf"
	"fmt"
	"io"

	"github.com/go-delve/delve/pkg/dwarf/regnum"
	"github.com/go-kit/log"

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

func (ptb *UnwindTableBuilder) UnwindTableForPid(pid int) (UnwindTable, error) {
	return UnwindTable{}, nil
}

func registerToString(reg uint64) string {
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
	fdes, err := ptb.readFDEs(path, 0)
	if err != nil {
		return err
	}

	for _, fde := range fdes {
		fmt.Fprintf(writer, "=> Function start: %x, Function end: %x\n", fde.Begin(), fde.End())
		tableRows := buildTableRows(fde)
		fmt.Fprintf(writer, "\t(found %d rows)\n", len(tableRows))
		for _, tableRow := range tableRows {
			CFAReg := registerToString(tableRow.CFA.Reg)

			fmt.Fprintf(writer, "\tLoc: %x CFA: $%s=%-4d", tableRow.Loc, CFAReg, tableRow.CFA.Offset)

			if tableRow.RBP.Op == OpUnimplemented || tableRow.RBP.Offset == 0 {
				fmt.Fprintf(writer, "\tRBP: u")
			} else {
				fmt.Fprintf(writer, "\tRBP: c%-4d", tableRow.RBP.Offset)
			}

			fmt.Fprintf(writer, "\n")
		}
	}

	return nil
}

func (ptb *UnwindTableBuilder) readFDEs(path string, start uint64) (frame.FrameDescriptionEntries, error) {
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
	fdes, err := frame.Parse(ehFrame, obj.ByteOrder, start, pointerSize(obj.Machine), sec.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame data: %w", err)
	}

	return fdes, nil
}

func buildTable(fdes frame.FrameDescriptionEntries) UnwindTable {
	table := make(UnwindTable, 0, len(fdes))
	for _, fde := range fdes {
		table = append(table, buildTableRows(fde)...)
	}
	return table
}

// UnwindTableRow represents a single row in the plan table.
// x86_64: rip (instruction pointer register), rsp (stack pointer register), rbp (base pointer/frame pointer register)
// aarch64: lr, sp, fp
type UnwindTableRow struct {
	// The address of the machine instruction.
	// Each row covers a range of machine instruction, from its address (Loc) to that of the row below.
	Loc uint64
	// CFA offset to find the return address.
	RA Instruction
	// CFA (could be an offset from $rsp or $rbp in x86_64) or an expression.
	CFA Instruction
	// RBP value.
	RBP Instruction
}

// TODO(kakkoyun): Maybe use CFA and RA for the field names.
// Op represents an operation to identify the unwind calculation that needs to be done,
// - to calculate address of the given register.
type Op uint8

const (
	// This type of register is not supported.
	OpUnimplemented Op = iota
	// Undefined register. The value will be defined at some later IP in the same DIE.
	OpUndefined
	// Value stored at some offset from "CFA".
	OpCFAOffset
	// Value of a machine register plus offset.
	OpRegister
)

// Instruction represents an instruction to unwind the address of a register.
type Instruction struct {
	Op     Op
	Reg    uint64
	Offset int64
}

func buildTableRows(fde *frame.FrameDescriptionEntry) []UnwindTableRow {
	rows := make([]UnwindTableRow, 0)

	frameContext := frame.ExecuteDwarfProgram(fde)

	instructionContexts := frameContext.InstructionContexts()

	for _, instructionContext := range instructionContexts {
		// fmt.Println("ret addr:", instructionContext.RetAddrReg)

		row := UnwindTableRow{
			Loc: instructionContext.Loc(),
		}

		// Deal with return address register ($rax)
		{
			rule, found := instructionContext.Regs[instructionContext.RetAddrReg]
			if found {
				// nolint:exhaustive
				switch rule.Rule {
				case frame.RuleOffset:
					row.RA = Instruction{Op: OpCFAOffset, Offset: rule.Offset}
				case frame.RuleUndefined:
					row.RA = Instruction{Op: OpUndefined}
				default:
					row.RA = Instruction{Op: OpUnimplemented}
				}
			} else {
				row.RA = Instruction{Op: OpUnimplemented}
			}
		}

		// Deal with $rbp
		{
			rule, found := instructionContext.Regs[regnum.AMD64_Rbp]
			if found {
				// nolint:exhaustive
				switch rule.Rule {
				case frame.RuleOffset:
					row.RBP = Instruction{Op: OpCFAOffset, Offset: rule.Offset}
				case frame.RuleUndefined:
					row.RBP = Instruction{Op: OpUndefined}
				default:
					row.RBP = Instruction{Op: OpUnimplemented}
				}
			} else {
				row.RBP = Instruction{Op: OpUnimplemented}
			}
		}

		row.CFA = Instruction{Op: OpRegister, Reg: instructionContext.CFA.Reg, Offset: instructionContext.CFA.Offset}
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
