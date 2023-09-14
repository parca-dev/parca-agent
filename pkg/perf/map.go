// Copyright 2023 The Parca Authors
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

package perf

import (
	"errors"
	"sort"
)

var ErrNoSymbolFound = errors.New("no symbol found")

type MapAddr struct {
	Start  uint64
	End    uint64
	Symbol string
}

type Map struct {
	addrs []MapAddr
}

func (p *Map) Deduplicate() *Map {
	newAddrs := make([]MapAddr, len(p.addrs))

	j := len(p.addrs) - 1
	for i := len(p.addrs) - 1; i >= 0; i-- {
		// The last symbol is the most up to date one, so if any earlier ones
		// intersect with it we only keep the latest one.
		if i > 0 && p.addrs[i-1].End > p.addrs[i].Start {
			continue
		}
		newAddrs[j] = p.addrs[i]
		j--
	}

	return &Map{
		addrs: newAddrs[j+1:],
	}
}

func (p *Map) Lookup(addr uint64) (string, error) {
	idx := sort.Search(len(p.addrs), func(i int) bool {
		return addr < p.addrs[i].End
	})
	if idx == len(p.addrs) || p.addrs[idx].Start > addr {
		return "", ErrNoSymbolFound
	}

	return p.addrs[idx].Symbol, nil
}
