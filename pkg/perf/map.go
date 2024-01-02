// Copyright 2023-2024 The Parca Authors
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

	"github.com/RoaringBitmap/roaring"
)

var ErrNoSymbolFound = errors.New("no symbol found")

type MapAddr struct {
	Start        uint64
	End          uint64
	SymbolOffset uint32
	SymbolLen    uint16
}

type Map struct {
	Path string

	addrs []MapAddr
}

func (p *Map) DeduplicatedIndices() *roaring.Bitmap {
	bm := roaring.NewBitmap()

	for i := len(p.addrs) - 1; i >= 0; i-- {
		// The last symbol is the most up to date one, so if any earlier ones
		// intersect with it we only keep the latest one. This works because
		// the list has been previously sorted.
		if i > 0 && p.addrs[i-1].End > p.addrs[i].Start {
			continue
		}

		bm.Add(uint32(i))
	}

	return bm
}
