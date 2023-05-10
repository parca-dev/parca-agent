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

package vdso

import (
	"fmt"

	"go.uber.org/multierr"

	"github.com/parca-dev/parca/pkg/symbol/symbolsearcher"

	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
)

type Cache struct {
	searcher symbolsearcher.Searcher
	f        string
}

func NewCache(objFilePool *objectfile.Pool) (*Cache, error) {
	kernelVersion, err := metadata.KernelRelease()
	if err != nil {
		return nil, err
	}
	var (
		objFile *objectfile.ObjectFile
		merr    error
		path    string
	)
	// find a file is enough
	for _, vdso := range []string{"vdso.so", "vdso64.so"} {
		path = fmt.Sprintf("/usr/lib/modules/%s/vdso/%s", kernelVersion, vdso)
		objFile, err = objFilePool.Open(path)
		if err != nil {
			merr = multierr.Append(merr, fmt.Errorf("failed to open elf file:%s, err:%w", path, err))
			continue
		}
		break
	}
	if objFile == nil {
		return nil, merr
	}
	defer objFile.Close()

	ef, err := objFile.ELF()
	if err != nil {
		return nil, fmt.Errorf("failed to get elf file:%s, err:%w", path, err)
	}

	// output of readelf --dyn-syms vdso.so:
	//  Num:    Value          Size Type    Bind   Vis      Ndx Name
	//     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
	//     1: ffffffffff700354     0 SECTION LOCAL  DEFAULT    7
	//     2: ffffffffff700700  1389 FUNC    WEAK   DEFAULT   13 clock_gettime@@LINUX_2.6
	//     3: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  ABS LINUX_2.6
	//     4: ffffffffff700c70   734 FUNC    GLOBAL DEFAULT   13 __vdso_gettimeofday@@LINUX_2.6
	//     5: ffffffffff700f70    61 FUNC    GLOBAL DEFAULT   13 __vdso_getcpu@@LINUX_2.6
	//     6: ffffffffff700c70   734 FUNC    WEAK   DEFAULT   13 gettimeofday@@LINUX_2.6
	//     7: ffffffffff700f50    22 FUNC    WEAK   DEFAULT   13 time@@LINUX_2.6
	//     8: ffffffffff700f70    61 FUNC    WEAK   DEFAULT   13 getcpu@@LINUX_2.6
	//     9: ffffffffff700700  1389 FUNC    GLOBAL DEFAULT   13 __vdso_clock_gettime@@LINUX_2.6
	//    10: ffffffffff700f50    22 FUNC    GLOBAL DEFAULT   13 __vdso_time@@LINUX_2.6
	syms, err := ef.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	return &Cache{searcher: symbolsearcher.New(syms), f: path}, nil
}

func (c *Cache) Resolve(addr uint64, m *process.Mapping) (string, error) {
	addr, err := m.Normalize(addr)
	if err != nil {
		return "", err
	}
	return c.searcher.Search(addr)
}
