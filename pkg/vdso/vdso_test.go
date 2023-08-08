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

package vdso

import (
	"debug/elf"
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/parca-dev/parca/pkg/symbol/symbolsearcher"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
)

func TestCache_Resolve(t *testing.T) {
	symbols := []elf.Symbol{
		{
			Name:    "clock_gettime@@LINUX_2.6",
			Value:   uint64(0x5400000),
			Size:    1389,
			Info:    byte(elf.STT_FUNC),
			Section: 13,
		},
		{
			Name:    "__vdso_gettimeofday@@LINUX_2.6",
			Value:   uint64(0x5402000),
			Size:    734,
			Info:    byte(elf.STT_FUNC),
			Section: 13,
		},
	}

	cache := &Cache{
		searcher: symbolsearcher.New(symbols),
		metrics:  newMetrics(prometheus.NewRegistry()),
	}

	fs, err := procfs.NewDefaultFS()
	require.NoError(t, err, "Expected no error")

	ofp := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 10, 1)
	mm := process.NewMapManager(prometheus.NewRegistry(), fs, ofp, false)
	m, err := mm.NewUserMapping(&procfs.ProcMap{}, os.Getpid())
	require.NoError(t, err, "Expected no error")

	// addr is smaller than the smallest symbol's value, symbol not found
	addr := uint64(0x2000000)
	symbol, err := cache.Resolve(m, addr)
	require.Error(t, err, "Expected an error for symbol not found")
	require.Empty(t, symbol, "Expected empty symbol")

	// addr in range, check symbol with value just less than addr
	addr = uint64(0x5401000)
	symbol, err = cache.Resolve(m, addr)
	require.NoError(t, err, "Expected no error")
	require.Equal(t, "clock_gettime@@LINUX_2.6", symbol, "Expected symbol 'clock_gettime@@LINUX_2.6'")

	// addr is larger than the largest symbol's value, check for symbol with largest value
	addr = uint64(0x6000000)
	symbol, err = cache.Resolve(m, addr)
	require.NoError(t, err, "Expected no error")
	require.Equal(t, "__vdso_gettimeofday@@LINUX_2.6", symbol, "Expected symbol '__vdso_gettimeofday@@LINUX_2.6'")
}
