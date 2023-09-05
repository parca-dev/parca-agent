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
	"fmt"
	"sort"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

type BpfCfaType uint16

// Constants are just to denote the rule type of calculation we do
// i.e whether we should compute based on rbp or rsp.
const (
	//nolint: deadcode,varcheck,unused
	// iota assigns a value to constants automatically.
	cfaTypeUndefined BpfCfaType = iota
	cfaTypeRbp
	cfaTypeRsp
	cfaTypeExpression
	cfaTypeEndFdeMarker
)

type bpfRbpType uint16

const (
	rbpRuleOffsetUnchanged bpfRbpType = iota
	rbpRuleOffset
	rbpRuleRegister
	rbpTypeExpression
	rbpTypeUndefinedReturnAddress
)

// CompactUnwindTableRows encodes unwind information using 2x 64 bit words.
// `lrOffset` is the link register for arm64; it is initialized to 0 for x86.
type CompactUnwindTableRow struct {
	pc        uint64
	lrOffset  int16
	cfaType   uint8
	rbpType   uint8
	cfaOffset int16
	rbpOffset int16
}

func (cutr *CompactUnwindTableRow) Pc() uint64 {
	return cutr.pc
}

func (cutr *CompactUnwindTableRow) LrOffset() int16 {
	return cutr.lrOffset
}

func (cutr *CompactUnwindTableRow) CfaType() uint8 {
	return cutr.cfaType
}

func (cutr *CompactUnwindTableRow) RbpType() uint8 {
	return cutr.rbpType
}

func (cutr *CompactUnwindTableRow) CfaOffset() int16 {
	return cutr.cfaOffset
}

func (cutr *CompactUnwindTableRow) RbpOffset() int16 {
	return cutr.rbpOffset
}

func (cutr *CompactUnwindTableRow) IsEndOfFDEMarker() bool {
	return cutr.cfaType == uint8(cfaTypeEndFdeMarker)
}

type CompactUnwindTable []CompactUnwindTableRow

func (t CompactUnwindTable) Len() int           { return len(t) }
func (t CompactUnwindTable) Less(i, j int) bool { return t[i].pc < t[j].pc }
func (t CompactUnwindTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

// BuildCompactUnwindTable produces a compact unwind table for the given
// frame description entries.
func BuildCompactUnwindTable(fdes frame.FrameDescriptionEntries, arch elf.Machine) (CompactUnwindTable, error) {
	table := make(CompactUnwindTable, 0, 4*len(fdes)) // heuristic: we expect each function to have ~4 unwind entries.
	for _, fde := range fdes {
		frameContext := frame.ExecuteDwarfProgram(fde, nil)
		for insCtx := frameContext.Next(); frameContext.HasNext(); insCtx = frameContext.Next() {
			row := unwindTableRow(insCtx)
			compactRow, err := rowToCompactRow(row, arch)
			if err != nil {
				return CompactUnwindTable{}, err
			}
			table = append(table, compactRow)
		}
		// Add a synthetic row for the end of the function.
		table = append(table, CompactUnwindTableRow{
			pc:      fde.End(),
			cfaType: uint8(cfaTypeEndFdeMarker),
		})
	}
	return table, nil
}

// rowToCompactRow converts an unwind row to a compact row.
func rowToCompactRow(row *UnwindTableRow, arch elf.Machine) (CompactUnwindTableRow, error) {
	var cfaType uint8
	var rbpType uint8
	var cfaOffset int16
	var rbpOffset int16
	var lrOffset int16

	// CFA.
	//nolint:exhaustive
	switch row.CFA.Rule {
	case frame.RuleCFA:
		if row.CFA.Reg == frame.X86_64FramePointer || row.CFA.Reg == frame.Arm64FramePointer {
			cfaType = uint8(cfaTypeRbp)
		} else if row.CFA.Reg == frame.X86_64StackPointer || row.CFA.Reg == frame.Arm64StackPointer {
			cfaType = uint8(cfaTypeRsp)
		}

		cfaOffset = int16(row.CFA.Offset)
		/*if row.CFA.Reg == frame.X86_64FramePointer && arch == elf.EM_X86_64 {
			cfaType = uint8(cfaTypeRbp)
		} else if row.CFA.Reg == frame.X86_64StackPointer && arch == elf.EM_X86_64 {
			cfaType = uint8(cfaTypeRsp)
		} else if row.CFA.Reg == frame.Arm64FramePointer && arch == elf.EM_AARCH64 {
			cfaType = uint8(cfaTypeFp)
		} else if row.CFA.Reg == frame.Arm64StackPointer && arch == elf.EM_AARCH64 {
			cfaType = uint8(cfaTypeSp) // TODO(sylfrena): Reuse cfaTypeRsp
		}*/
	case frame.RuleExpression:
		cfaType = uint8(cfaTypeExpression)
		cfaOffset = int16(ExpressionIdentifier(row.CFA.Expression, arch))
	default:
		return CompactUnwindTableRow{}, fmt.Errorf("CFA rule is not valid: %d", row.CFA.Rule)
	}

	// Frame pointer.
	switch row.RBP.Rule {
	case frame.RuleOffset:
		rbpType = uint8(rbpRuleOffset)
		// TODO(sylfrena): Reuse type DELET
		// if arch == elf.EM_AARCH64 {
		//	rbpType = uint8(fpRuleOffset) // Use one type here
		// }
		rbpOffset = int16(row.RBP.Offset)
		// curious that the following condition doesn't satisfy. it should.
		// On further investigation, it doesn't because only Offset Rule is applied, and register value is x0, not x29
		// Ideally this whole thing should work with just rbpType = uint8(reusedrbp/fpRuleOffset)
		// TODO(sylfrena): Delete this part later
		// if row.RBP.Reg == frame.Arm64FramePointer && arch == elf.EM_AARCH64 {
		// fmt.Println("Rule fp Offset(arm64)")
		//	rbpType = uint8(fpRuleOffset)
		// }
	// TODO(sylfrena): Do these conditions also cover Arm64 DWARF?
	case frame.RuleRegister:
		rbpType = uint8(rbpRuleRegister)
		// fmt.Println("rbp RuleRegister")
	case frame.RuleExpression:
		rbpType = uint8(rbpTypeExpression)
		// fmt.Println("rbp RuleExpression")
	case frame.RuleUndefined:
		// fmt.Println("rbp RuleUndefined")
	case frame.RuleUnknown:
	case frame.RuleSameVal:
	case frame.RuleValOffset:
	case frame.RuleValExpression:
	case frame.RuleCFA:
	}

	// Return address.
	//nolint:exhaustive
	switch row.RA.Rule {
	case frame.RuleOffset:
		if arch == elf.EM_X86_64 {
			// fmt.Println("RA RuleOffset for x86")
			lrOffset = 0
		} else if arch == elf.EM_AARCH64 {
			// fmt.Println("RA RuleOffset for Arm64")
			lrOffset = int16(row.RA.Offset)
		}

	case frame.RuleCFA:
		// fmt.Println("Rule CFA: RA")
	case frame.RuleRegister:
	case frame.RuleUnknown:
		// fmt.Println("Rule Unknown: RA")
	case frame.RuleUndefined:
		// fmt.Println("Rule Undefined: RA")
		// TODO(sylfrena): Investigate what happens if we remove the condition below
		// Why are we setting rbpType in RA Rule switch?
		if arch == elf.EM_X86_64 {
			rbpType = uint8(rbpTypeUndefinedReturnAddress)
		}
	}

	return CompactUnwindTableRow{
		pc:        row.Loc,
		lrOffset:  lrOffset,
		cfaType:   cfaType,
		rbpType:   rbpType,
		cfaOffset: cfaOffset,
		rbpOffset: rbpOffset,
	}, nil
}

// compactUnwindTableRepresentation converts an unwind table to its compact table
// representation.
func CompactUnwindTableRepresentation(unwindTable UnwindTable, arch elf.Machine) (CompactUnwindTable, error) {
	compactTable := make(CompactUnwindTable, 0, len(unwindTable))

	for i := range unwindTable {
		row := unwindTable[i]

		compactRow, err := rowToCompactRow(&row, arch)
		if err != nil {
			return CompactUnwindTable{}, err
		}

		compactTable = append(compactTable, compactRow)
	}

	return compactTable, nil
}

// GenerateCompactUnwindTable produces the compact unwind table for a given
// executable.
func GenerateCompactUnwindTable(fullExecutablePath, executable string) (CompactUnwindTable, error) {
	var ut CompactUnwindTable

	// Fetch FDEs.
	fdes, arch, err := ReadFDEs(fullExecutablePath)
	if err != nil {
		return ut, err
	}

	// Sort them, as this will ensure that the generated table
	// is also sorted. Sorting fewer elements will be faster.
	sort.Sort(fdes)

	// Generate the compact unwind table.
	ut, err = BuildCompactUnwindTable(fdes, arch)
	if err != nil {
		return ut, err
	}

	// This should not be necessary, as per the sorting above, but
	// just in case, as we need it sorted. Checking whether the slice
	// was already sorted with `slices.IsSortedFunc()`, did not show
	// any improvements. See benchmark in the test file.
	sort.Sort(ut)

	return ut, nil
}
