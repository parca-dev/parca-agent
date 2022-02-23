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

package maps

import (
	"testing"

	"github.com/go-kit/log"
	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

func testCache() *PIDMappingFileCache {
	return &PIDMappingFileCache{
		fs: testutil.NewFakeFS(map[string][]byte{
			"/proc/2043862/maps": []byte(`
00400000-00464000 r-xp 00000000 fd:01 2106801                            /main
00464000-004d4000 r--p 00064000 fd:01 2106801                            /main
004d4000-004d9000 rw-p 000d4000 fd:01 2106801                            /main
004d9000-0050b000 rw-p 00000000 00:00 0
c000000000-c004000000 rw-p 00000000 00:00 0
7f47d6714000-7f47d8a85000 rw-p 00000000 00:00 0
7f47d8a85000-7f47e8c05000 ---p 00000000 00:00 0
7f47e8c05000-7f47e8c06000 rw-p 00000000 00:00 0
7f47e8c06000-7f47faab5000 ---p 00000000 00:00 0
7f47faab5000-7f47faab6000 rw-p 00000000 00:00 0
7f47faab6000-7f47fce8b000 ---p 00000000 00:00 0
7f47fce8b000-7f47fce8c000 rw-p 00000000 00:00 0
7f47fce8c000-7f47fd305000 ---p 00000000 00:00 0
7f47fd305000-7f47fd306000 rw-p 00000000 00:00 0
7f47fd306000-7f47fd385000 ---p 00000000 00:00 0
7f47fd385000-7f47fd3e5000 rw-p 00000000 00:00 0
7ffc30d8b000-7ffc30dac000 rw-p 00000000 00:00 0                          [stack]
7ffc30dce000-7ffc30dd1000 r--p 00000000 00:00 0                          [vvar]
7ffc30dd1000-7ffc30dd3000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
			`),
		}),
		logger:     log.NewNopLogger(),
		cache:      map[uint32][]*profile.Mapping{},
		pidMapHash: map[uint32]uint64{},
	}
}

func TestPIDMappingFileCache(t *testing.T) {
	c := testCache()
	mapping, err := c.MappingForPID(2043862)
	require.NoError(t, err)
	require.Equal(t, 3, len(mapping))
}

func TestMapping(t *testing.T) {
	m := &Mapping{
		fileCache:   testCache(),
		pidMappings: map[uint32][]*profile.Mapping{},
		pids:        []uint32{},
	}
	mapping, err := m.PIDAddrMapping(2043862, 0x45e427)
	require.NoError(t, err)
	require.NotNil(t, mapping)

	resultMappings, _ := m.AllMappings()
	require.Equal(t, 3, len(resultMappings))
}
