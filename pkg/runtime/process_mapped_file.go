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

package runtime

import (
	"debug/elf"
	"fmt"
	"os"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/elfreader"
)

type ProcessMappedFile struct {
	pid int

	*os.File
	elfFile *elf.File

	start uint64

	cache *cache.Cache[string, uint64]
}

func NewProcessMappedFile(pid int, f *os.File, start uint64) (*ProcessMappedFile, error) {
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("new file: %w", err)
	}
	cache := cache.NewLRUCache[string, uint64](
		prometheus.NewRegistry(), // no need to track this cache metrics.
		32,
	)
	return &ProcessMappedFile{
		pid:     pid,
		File:    f,
		elfFile: ef,
		start:   start,
		cache:   cache,
	}, nil
}

func (pmf ProcessMappedFile) Close() error {
	return pmf.File.Close()
}

func (pmf ProcessMappedFile) VersionFromBSS(rgx *regexp.Regexp) (string, error) {
	return scanProcessBSSForVersion(pmf.pid, pmf.File, pmf.loadBaseAddress(), rgx)
}

func (pmf ProcessMappedFile) VersionFromRodata(rgx *regexp.Regexp) (string, error) {
	return ScanRodataForVersion(pmf.File, rgx)
}

func (pmf ProcessMappedFile) loadBaseAddress() uint64 {
	// p_vaddr may be larger than the map address in case when the header has an offset and
	// the map address is relatively small. In this case we can default to 0.
	header := elfreader.FindTextProgHeader(pmf.elfFile)
	if header == nil {
		return pmf.start
	}
	// return pmf.start - header.Vaddr
	return saturatingSub(pmf.start, header.Vaddr)
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

func (pmf ProcessMappedFile) FindAddressOf(s string) (uint64, error) {
	addr, ok := pmf.cache.Get(s)
	if ok {
		return addr, nil
	}
	// Search in both symbol and dynamic symbol tables.
	symbol, err := FindSymbol(pmf.elfFile, s)
	if err != nil {
		return 0, fmt.Errorf("FindSymbol: %w", err)
	}
	// Memoize the result.
	addr = symbol.Value + pmf.loadBaseAddress()
	pmf.cache.Add(s, addr)
	return addr, nil
}
