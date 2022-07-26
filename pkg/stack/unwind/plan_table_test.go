// Copyright 2021 The Parca Authors
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

package unwind

import (
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/maps"
)

func TestBuildPlanTable(t *testing.T) {
	logger := log.NewNopLogger()
	ptb := NewPlanTableBuilder(logger, maps.NewPIDMappingFileCache(logger))

	fdes, err := ptb.readFDEs("testdata/pie-dynamic", 0)
	require.NoError(t, err)

	planTable := buildTable(fdes)
	require.Equal(t, len(fdes), len(planTable))
	require.Equal(t, uint64(0xfb6960), planTable[0].Begin)
	require.Equal(t, uint64(0xfb698f), planTable[0].End)
	require.Equal(t, Instruction{Op: OpUndefined}, planTable[0].RIP)
	require.Equal(t, Instruction{Op: 3, Reg: 0x7, Off: 8}, planTable[0].RSP)
}
