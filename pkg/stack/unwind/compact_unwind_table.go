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
//

package unwind

import (
	"bytes"
	"debug/elf"
	"fmt"
	"sort"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

type BpfCfaType uint8

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

func NewCompactUnwindTableRow(pc uint64, lrOffset int16, cfaType, rbpType uint8, cfaOffset, rbpOffset int16) CompactUnwindTableRow {
	return CompactUnwindTableRow{
		pc,
		lrOffset,
		cfaType,
		rbpType,
		cfaOffset,
		rbpOffset,
	}
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

func (cutr *CompactUnwindTableRow) ToString(showLr bool) string {
	r := bytes.NewBufferString("")

	fmt.Fprintf(r, "pc: %x ", cutr.Pc())
	fmt.Fprintf(r, "cfa_type: %-2d ", cutr.CfaType())
	fmt.Fprintf(r, "rbp_type: %-2d ", cutr.RbpType())
	fmt.Fprintf(r, "cfa_offset: %-4d ", cutr.CfaOffset())
	fmt.Fprintf(r, "rbp_offset: %-4d", cutr.RbpOffset())
	if showLr {
		fmt.Fprintf(r, "lr_offset: %-4d", cutr.LrOffset())
	}

	return r.String()
}

func (cutr *CompactUnwindTableRow) IsRedundant(other *CompactUnwindTableRow) bool {
	if cutr == nil {
		return false
	}
	return cutr.lrOffset == other.lrOffset &&
		cutr.cfaType == other.cfaType &&
		cutr.rbpType == other.rbpType &&
		cutr.cfaOffset == other.cfaOffset &&
		cutr.rbpOffset == other.rbpOffset
}

type CompactUnwindTable []CompactUnwindTableRow

func (t CompactUnwindTable) Len() int           { return len(t) }
func (t CompactUnwindTable) Less(i, j int) bool { return t[i].pc < t[j].pc }
func (t CompactUnwindTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

// RemoveRedundant removes redudant unwind rows in place.
func (t CompactUnwindTable) RemoveRedundant() CompactUnwindTable {
	res := t[:0]
	var lastRow CompactUnwindTableRow
	for _, row := range t {
		row := row
		if lastRow.IsRedundant(&row) {
			continue
		}
		res = append(res, row)
		lastRow = row
	}
	return res
}

// BuildCompactUnwindTable produces a compact unwind table for the given
// frame description entries.
func BuildCompactUnwindTable(fdes frame.FrameDescriptionEntries, arch elf.Machine) (CompactUnwindTable, error) {
	table := make(CompactUnwindTable, 0, 4*len(fdes)) // heuristic: we expect each function to have ~4 unwind entries.
	context := frame.NewContext()
	lastFunctionPc := uint64(0)
	for _, fde := range fdes {
		// We use pc=0 as a sentinel so we can't have that, however some debug
		// files have FDE's with offset 0, usually empty or tiny but not always.
		// There's probably a better way to filter these but this works, we
		// panic over in maps.setUnwindTableForMapping if any start at 0.
		// An example is the alpine "ld-musl-x86_64.so.1.debug".
		if fde.Begin() == 0 {
			continue
		}
		// Add a synthetic row at the end of the function but only
		// if there's a gap between functions. Adding it at the end
		// of every function can result in duplicated unwind rows for
		// the same PC. This would not be correct a it can result in
		// stopping the unwinding earlier than we should and that stack
		// will be dropped.
		if lastFunctionPc != 0 && fde.Begin() != lastFunctionPc {
			table = append(table, CompactUnwindTableRow{
				pc:      lastFunctionPc,
				cfaType: uint8(cfaTypeEndFdeMarker),
			})
		}

		frameContext, err := frame.ExecuteDWARFProgram(fde, context)
		if err != nil {
			return CompactUnwindTable{}, err
		}

		for {
			insCtx, err := frameContext.Next()
			if err != nil {
				return CompactUnwindTable{}, err
			}

			if !frameContext.HasNext() {
				break
			}

			row := unwindTableRow(insCtx)
			compactRow, err := rowToCompactRow(row, arch)
			if err != nil {
				return CompactUnwindTable{}, err
			}
			table = append(table, compactRow)
		}
		lastFunctionPc = fde.End()
	}
	// Add a synthetic row at the end of the unwind table. It is fine
	// if this unwind table's last PC is equal to the next unwind table's first
	// PC as we won't cross this boundary while binary searching.
	table = append(table, CompactUnwindTableRow{
		pc:      lastFunctionPc,
		cfaType: uint8(cfaTypeEndFdeMarker),
	})
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
		rbpOffset = int16(row.RBP.Offset)
	case frame.RuleRegister:
		rbpType = uint8(rbpRuleRegister)
	case frame.RuleExpression:
		rbpType = uint8(rbpTypeExpression)
	case frame.RuleUndefined:
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
			lrOffset = 0
		} else if arch == elf.EM_AARCH64 {
			lrOffset = int16(row.RA.Offset)
		}

	case frame.RuleCFA:
	case frame.RuleRegister:
	case frame.RuleUnknown:
	case frame.RuleUndefined:
		rbpType = uint8(rbpTypeUndefinedReturnAddress)
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
func GenerateCompactUnwindTable(uc *UnwindContext, root, exe string) (CompactUnwindTable, elf.Machine, frame.FrameDescriptionEntries, error) {
	var ut CompactUnwindTable

	// Fetch FDEs.
	fdes, arch, err := ReadFDEs(uc, root, exe)
	if err != nil {
		return ut, arch, fdes, err
	}

	// Sort them, as this will ensure that the generated table
	// is also sorted. Sorting fewer elements will be faster.
	sort.Sort(fdes)

	// Generate the compact unwind table.
	ut, err = BuildCompactUnwindTable(fdes, arch)
	if err != nil {
		return ut, arch, fdes, fmt.Errorf("build compact unwind table for executable %q: %w", exe, err)
	}

	// This should not be necessary, as per the sorting above, but
	// just in case, as we need it sorted. Checking whether the slice
	// was already sorted with `slices.IsSortedFunc()`, did not show
	// any improvements. See benchmark in the test file.
	sort.Sort(ut)

	// Remove redundant rows.
	return ut.RemoveRedundant(), arch, fdes, nil
}
