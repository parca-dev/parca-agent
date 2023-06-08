// Copyright 2022-2023 The Parca Authors
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
	"errors"
	"fmt"
	"io"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-multierror"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

var (
	ErrNoFDEsFound            = errors.New("no FDEs found")
	ErrEhFrameSectionNotFound = errors.New("failed to find .eh_frame section")
)

type UnwindTableBuilder struct {
	logger log.Logger
}

func NewUnwindTableBuilder(logger log.Logger) *UnwindTableBuilder {
	return &UnwindTableBuilder{logger: logger}
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
func (ptb *UnwindTableBuilder) PrintTable(writer io.Writer, path string, compact bool, pc *uint64) error {
	fdes, err := ReadFDEs(path)
	if err != nil {
		return err
	}

	// The frame package can raise in case of malformed unwind data.
	defer func() {
		if r := recover(); r != nil {
			level.Info(ptb.logger).Log("msg", "recovered a panic in PrintTable", "stack", r)
		}
	}()

	unwindContext := frame.NewContext()
	for _, fde := range fdes {
		if pc != nil {
			if fde.Begin() > *pc || *pc > fde.End() {
				continue
			}
		}

		fmt.Fprintf(writer, "=> Function start: %x, Function end: %x\n", fde.Begin(), fde.End())

		frameContext := frame.ExecuteDwarfProgram(fde, unwindContext)
		for insCtx := frameContext.Next(); frameContext.HasNext(); insCtx = frameContext.Next() {
			unwindRow := unwindTableRow(insCtx)

			if unwindRow == nil {
				break
			}

			if compact {
				compactRow, err := rowToCompactRow(unwindRow)
				if err != nil {
					return err
				}

				fmt.Fprintf(writer, "\t")
				fmt.Fprintf(writer, "pc: %x ", compactRow.Pc())
				fmt.Fprintf(writer, "cfa_type: %-2d ", compactRow.CfaType())
				fmt.Fprintf(writer, "rbp_type: %-2d ", compactRow.RbpType())
				fmt.Fprintf(writer, "cfa_offset: %-4d ", compactRow.CfaOffset())
				fmt.Fprintf(writer, "rbp_offset: %-4d", compactRow.RbpOffset())
				fmt.Fprintf(writer, "\n")
			} else {
				//nolint:exhaustive
				switch unwindRow.CFA.Rule {
				case frame.RuleCFA:
					CFAReg := x64RegisterToString(unwindRow.CFA.Reg)
					fmt.Fprintf(writer, "\tLoc: %x CFA: $%s=%-4d", unwindRow.Loc, CFAReg, unwindRow.CFA.Offset)
				case frame.RuleExpression:
					expressionID := ExpressionIdentifier(unwindRow.CFA.Expression)
					if expressionID == ExpressionUnknown {
						fmt.Fprintf(writer, "\tLoc: %x CFA: exp     ", unwindRow.Loc)
					} else {
						fmt.Fprintf(writer, "\tLoc: %x CFA: exp (plt %d)", unwindRow.Loc, expressionID)
					}
				default:
					return multierror.Append(fmt.Errorf("CFA rule is not valid. This should never happen"))
				}

				// RuleRegister
				//nolint:exhaustive
				switch unwindRow.RBP.Rule {
				case frame.RuleUndefined, frame.RuleUnknown:
					fmt.Fprintf(writer, "\tRBP: u")
				case frame.RuleRegister:
					RBPReg := x64RegisterToString(unwindRow.RBP.Reg)
					fmt.Fprintf(writer, "\tRBP: $%s", RBPReg)
				case frame.RuleOffset:
					fmt.Fprintf(writer, "\tRBP: c%-4d", unwindRow.RBP.Offset)
				case frame.RuleExpression:
					fmt.Fprintf(writer, "\tRBP: exp")
				default:
					panic(fmt.Sprintf("Got rule %d for RBP, which wasn't expected", unwindRow.RBP.Rule))
				}

				fmt.Fprintf(writer, "\n")
			}
		}
	}

	return nil
}

func ReadFDEs(path string) (frame.FrameDescriptionEntries, error) {
	// TODO(kakkoyun): Migrate objectfile and pool.
	obj, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open elf: %w", err)
	}
	defer obj.Close()

	sec := obj.Section(".eh_frame")
	if sec == nil {
		return nil, ErrEhFrameSectionNotFound
	}

	// TODO: Consider using the debug_frame section as a fallback.
	// TODO: Needs to support DWARF64 as well.
	ehFrame, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .eh_frame section: %w", err)
	}

	// TODO: Byte order of a DWARF section can be different.
	fdes, err := frame.Parse(ehFrame, obj.ByteOrder, 0, pointerSize(obj.Machine), sec.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame data: %w", err)
	}

	if len(fdes) == 0 {
		return nil, ErrNoFDEsFound
	}

	return fdes, nil
}

func BuildUnwindTable(fdes frame.FrameDescriptionEntries) UnwindTable {
	// The frame package can raise in case of malformed unwind data.
	table := make(UnwindTable, 0, 4*len(fdes)) // heuristic

	for _, fde := range fdes {
		frameContext := frame.ExecuteDwarfProgram(fde, nil)
		for insCtx := frameContext.Next(); frameContext.HasNext(); insCtx = frameContext.Next() {
			table = append(table, *unwindTableRow(insCtx))
		}
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

type UnwindTable []UnwindTableRow

func (t UnwindTable) Len() int           { return len(t) }
func (t UnwindTable) Less(i, j int) bool { return t[i].Loc < t[j].Loc }
func (t UnwindTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

func unwindTableRow(instructionContext *frame.InstructionContext) *UnwindTableRow {
	if instructionContext == nil {
		return nil
	}

	return &UnwindTableRow{
		Loc: instructionContext.Loc(),
		CFA: instructionContext.CFA,
		RA:  instructionContext.Regs.SavedReturn,
		RBP: instructionContext.Regs.FramePointer,
	}
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
