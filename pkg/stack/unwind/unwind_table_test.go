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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

// TODO(Sylfrena): Add equivalent test for arm64.
func TestBuildUnwindTable(t *testing.T) {
	fdes, _, err := ReadFDEs("../../../testdata/out/amd64/basic-cpp")
	require.NoError(t, err)

	unwindTable, err := BuildUnwindTable(fdes)
	require.NoError(t, err)
	require.Len(t, unwindTable, 2762)

	require.Equal(t, uint64(0x20b6e0), unwindTable[0].Loc)
	require.Equal(t, uint64(0x224357), unwindTable[len(unwindTable)-1].Loc)

	require.Equal(t, frame.DWRule{Rule: frame.RuleUndefined, Offset: 0}, unwindTable[0].RA)
	require.Equal(t, frame.DWRule{Rule: frame.RuleCFA, Reg: 0x7, Offset: 8}, unwindTable[0].CFA)
	require.Equal(t, frame.DWRule{Rule: frame.RuleUnknown, Reg: 0x0, Offset: 0}, unwindTable[0].RBP)
}

func TestSpecialOpcodes(t *testing.T) {
	tests := []struct {
		name       string
		executable string
	}{
		{
			name:       "DW_CFA_GNU_window_save / DW_CFA_AARCH64_negate_ra_state",
			executable: "testdata/cfa_gnu_window_save",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fdes, _, err := ReadFDEs(tt.executable)
			require.NoError(t, err)

			unwindTable, err := BuildUnwindTable(fdes)
			require.NoError(t, err)
			require.NotEmpty(t, unwindTable)
		})
	}
}

var rbpOffsetResult int64

func benchmarkParsingDWARFUnwindInformation(b *testing.B, executable string) {
	b.Helper()
	b.ReportAllocs()

	var rbpOffset int64

	for n := 0; n < b.N; n++ {
		fdes, _, err := ReadFDEs(executable)
		if err != nil {
			panic("could not read FDEs")
		}

		unwindContext := frame.NewContext()
		for _, fde := range fdes {
			frameContext, err := frame.ExecuteDWARFProgram(fde, unwindContext)
			if err != nil {
				b.Fail()
			}

			for {
				insCtx, err := frameContext.Next()
				if err != nil {
					b.Fail()
				}

				if !frameContext.HasNext() {
					break
				}

				unwindRow := unwindTableRow(insCtx)
				if unwindRow.RBP.Rule == frame.RuleUndefined || unwindRow.RBP.Offset == 0 {
					// u
					rbpOffset = 0
				} else {
					rbpOffset = unwindRow.RBP.Offset
				}
			}
		}
	}
	// Make sure that the compiler won't optimize out the benchmark.
	rbpOffsetResult = rbpOffset
}

func BenchmarkParsingLibcUnwindInformation(b *testing.B) {
	benchmarkParsingDWARFUnwindInformation(b, "../../../testdata/vendored/x86/libc.so.6")
}

func BenchmarkParsingRedpandaUnwindInformation(b *testing.B) {
	benchmarkParsingDWARFUnwindInformation(b, "../../../testdata/vendored/x86/redpanda")
}
