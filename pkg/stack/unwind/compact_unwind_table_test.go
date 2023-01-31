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
	"testing"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"

	"github.com/stretchr/testify/require"
)

func TestCompactUnwindTable(t *testing.T) {
	tests := []struct {
		name    string
		input   UnwindTableRow
		want    CompactUnwindTableRow
		wantErr bool
	}{
		{
			name: "CFA with Offset on x86_64 stack pointer",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleCFA, Reg: frame.X86_64StackPointer, Offset: 8},
				RBP: frame.DWRule{Rule: frame.RuleUnknown},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},
			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           2,
				rbpType:           0,
				cfaOffset:         8,
				rbpOffset:         0,
			},
		},
		{
			name: "CFA with Offset on x86_64 frame pointer",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleCFA, Reg: frame.X86_64FramePointer, Offset: 8},
				RBP: frame.DWRule{Rule: frame.RuleUnknown},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           1,
				rbpType:           0,
				cfaOffset:         8,
				rbpOffset:         0,
			},
		},
		{
			name: "CFA known expression PLT 1",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleExpression, Expression: Plt1[:]},
				RBP: frame.DWRule{Rule: frame.RuleUnknown},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           3,
				rbpType:           0,
				cfaOffset:         1,
				rbpOffset:         0,
			},
		},
		{
			name: "CFA known expression PLT 2",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleExpression, Expression: Plt2[:]},
				RBP: frame.DWRule{Rule: frame.RuleUnknown},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           3,
				rbpType:           0,
				cfaOffset:         2,
				rbpOffset:         0,
			},
		},
		{
			name: "CFA not known expression",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleExpression, Expression: []byte{'l', 'o', 'l'}},
				RBP: frame.DWRule{Rule: frame.RuleUnknown},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           3,
				rbpType:           0,
				cfaOffset:         0,
				rbpOffset:         0,
			},
		},
		{
			name: "RBP offset",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleCFA, Reg: frame.X86_64StackPointer, Offset: 8},
				RBP: frame.DWRule{Rule: frame.RuleOffset, Offset: 64},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           2,
				rbpType:           1,
				cfaOffset:         8,
				rbpOffset:         64,
			},
		},
		{
			name: "RBP register",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleCFA, Reg: frame.X86_64StackPointer, Offset: 8},
				RBP: frame.DWRule{Rule: frame.RuleRegister, Reg: 0xBAD},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           2,
				rbpType:           2,
				cfaOffset:         8,
				rbpOffset:         0,
			},
		},
		{
			name: "RBP expression",
			input: UnwindTableRow{
				Loc: 123,
				CFA: frame.DWRule{Rule: frame.RuleCFA, Reg: frame.X86_64StackPointer, Offset: 8},
				RBP: frame.DWRule{Rule: frame.RuleExpression, Expression: Plt1[:]},
				RA:  frame.DWRule{Rule: frame.RuleOffset, Offset: -8},
			},

			want: CompactUnwindTableRow{
				pc:                123,
				_reservedDoNotUse: 0,
				cfaType:           2,
				rbpType:           3,
				cfaOffset:         8,
				rbpOffset:         0,
			},
		},
		{
			name:    "Invalid CFA rule returns error",
			input:   UnwindTableRow{},
			want:    CompactUnwindTableRow{},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			have, err := CompactUnwindTableRepresentation(UnwindTable{test.input})
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, CompactUnwindTable{test.want}, have)
			}
		})
	}
}
