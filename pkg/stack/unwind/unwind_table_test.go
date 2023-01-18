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
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
)

func TestBuildUnwindTable(t *testing.T) {
	logger := log.NewNopLogger()
	utb := NewUnwindTableBuilder(logger)

	fdes, err := utb.readFDEs("../../../testdata/out/basic-cpp")
	require.NoError(t, err)

	unwindTable := buildUnwindTable(fdes)
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

	logger := log.NewNopLogger()
	var rbpOffset int64
	utb := NewUnwindTableBuilder(logger)

	for n := 0; n < b.N; n++ {
		fdes, err := utb.readFDEs(executable)
		if err != nil {
			panic("could not read FDEs")
		}

		for _, fde := range fdes {
			frameContext := frame.ExecuteDwarfProgram(fde, nil)
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
	benchmarkParsingDwarfUnwindInformation(b, "../../../testdata/vendored/libc.so.6")
}

func BenchmarkParsingRedpandaUnwindInformation(b *testing.B) {
	benchmarkParsingDwarfUnwindInformation(b, "../../../testdata/vendored/redpanda")
}
