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
	"fmt"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

type BpfCfaType uint16

const (
	//nolint: deadcode,varcheck
	cfaTypeUndefined BpfCfaType = iota
	cfaTypeRbp
	cfaTypeRsp
	cfaTypeExpression
)

type BpfRbpType uint16

const (
	RbpRuleOffsetUnchanged BpfRbpType = iota
	RbpRuleOffset
	RbpRuleRegister
	rbpTypeExpression
)

// CompactUnwindTableRows encodes unwind information using 2x 64 bit words.
type CompactUnwindTableRow struct {
	pc                uint64
	_reservedDoNotUse uint16
	cfaType           uint8
	rbpType           uint8
	cfaOffset         int16
	rbpOffset         int16
}

func (cutr *CompactUnwindTableRow) Pc() uint64 {
	return cutr.pc
}

func (cutr *CompactUnwindTableRow) ReservedDoNotUse() uint16 {
	return cutr._reservedDoNotUse
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

type CompactUnwindTable []CompactUnwindTableRow

func (t CompactUnwindTable) Len() int           { return len(t) }
func (t CompactUnwindTable) Less(i, j int) bool { return t[i].pc < t[j].pc }
func (t CompactUnwindTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

// BuildCompactUnwindTable produces a compact unwind table for the given
// frame description entries.
func BuildCompactUnwindTable(fdes frame.FrameDescriptionEntries) (CompactUnwindTable, error) {
	table := make(CompactUnwindTable, 0, 4*len(fdes)) // heuristic: we expect each function to have ~4 unwind entries.
	for _, fde := range fdes {
		frameContext := frame.ExecuteDwarfProgram(fde, nil)
		for insCtx := frameContext.Next(); frameContext.HasNext(); insCtx = frameContext.Next() {
			row := unwindTableRow(insCtx)
			compactRow, err := rowToCompactRow(row)
			if err != nil {
				return CompactUnwindTable{}, err
			}
			table = append(table, compactRow)
		}
	}
	return table, nil
}

// rowToCompactRow converts an unwind row to a compact row.
func rowToCompactRow(row *UnwindTableRow) (CompactUnwindTableRow, error) {
	var cfaType uint8
	var rbpType uint8
	var cfaOffset int16
	var rbpOffset int16

	// CFA.
	//nolint:exhaustive
	switch row.CFA.Rule {
	case frame.RuleCFA:
		if row.CFA.Reg == frame.X86_64FramePointer {
			cfaType = uint8(cfaTypeRbp)
		} else if row.CFA.Reg == frame.X86_64StackPointer {
			cfaType = uint8(cfaTypeRsp)
		}
		cfaOffset = int16(row.CFA.Offset)
	case frame.RuleExpression:
		cfaType = uint8(cfaTypeExpression)
		cfaOffset = int16(ExpressionIdentifier(row.CFA.Expression))
	default:
		return CompactUnwindTableRow{}, fmt.Errorf("CFA rule is not valid: %d", row.CFA.Rule)
	}

	// Frame pointer.
	switch row.RBP.Rule {
	case frame.RuleOffset:
		rbpType = uint8(RbpRuleOffset)
		rbpOffset = int16(row.RBP.Offset)
	case frame.RuleRegister:
		rbpType = uint8(RbpRuleRegister)
	case frame.RuleExpression:
		rbpType = uint8(rbpTypeExpression)
	case frame.RuleUndefined:
	case frame.RuleUnknown:
	case frame.RuleSameVal:
	case frame.RuleValOffset:
	case frame.RuleValExpression:
	case frame.RuleCFA:
	}

	return CompactUnwindTableRow{
		pc:                row.Loc,
		_reservedDoNotUse: 0,
		cfaType:           cfaType,
		rbpType:           rbpType,
		cfaOffset:         cfaOffset,
		rbpOffset:         rbpOffset,
	}, nil
}

// CompactUnwindTableRepresentation converts an unwind table to its compact table
// representation.
func CompactUnwindTableRepresentation(unwindTable UnwindTable) (CompactUnwindTable, error) {
	compactTable := make(CompactUnwindTable, 0, len(unwindTable))

	for i := range unwindTable {
		row := unwindTable[i]

		compactRow, err := rowToCompactRow(&row)
		if err != nil {
			return CompactUnwindTable{}, err
		}

		compactTable = append(compactTable, compactRow)
	}

	return compactTable, nil
}
