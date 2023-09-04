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

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

func TestBuildUnwindTable(t *testing.T) {
	fdes, _, err := ReadFDEs("../../../testdata/out/x86/basic-cpp")
	require.NoError(t, err)

	unwindTable := BuildUnwindTable(fdes)
	require.Equal(t, 38, len(unwindTable))

	require.Equal(t, uint64(0x401020), unwindTable[0].Loc)
	require.Equal(t, uint64(0x40118e), unwindTable[len(unwindTable)-1].Loc)

	require.Equal(t, frame.DWRule{Rule: frame.RuleOffset, Offset: -8}, unwindTable[0].RA)
	require.Equal(t, frame.DWRule{Rule: frame.RuleCFA, Reg: 0x7, Offset: 8}, unwindTable[0].CFA)
	require.Equal(t, frame.DWRule{Rule: frame.RuleUnknown, Reg: 0x0, Offset: 0}, unwindTable[0].RBP)
}

var rbpOffsetResult int64

func benchmarkParsingDwarfUnwindInformation(b *testing.B, executable string) {
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
			frameContext := frame.ExecuteDwarfProgram(fde, unwindContext)
			for insCtx := frameContext.Next(); frameContext.HasNext(); insCtx = frameContext.Next() {
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
	benchmarkParsingDwarfUnwindInformation(b, "../../../testdata/vendored/x86/libc.so.6")
}

func BenchmarkParsingRedpandaUnwindInformation(b *testing.B) {
	benchmarkParsingDwarfUnwindInformation(b, "../../../testdata/vendored/x86/redpanda")
}
