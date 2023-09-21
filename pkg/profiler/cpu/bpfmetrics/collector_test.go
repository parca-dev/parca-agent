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

package bpfmetrics

import (
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"
)

func TestFdInfoMemlock(t *testing.T) {
	// 'data' is indentation-sensitive, please don't change indentation
	data := []byte(`pos:	0
flags:	02000002
mnt_id:	15
ino:	2081
map_type:	3
key_size:	4
value_size:	4
max_entries:	1
map_flags:	0x0
map_extra:	0x0
memlock:	4096
map_id:	551
frozen:	0
owner_prog_type:	7
owner_jited:	1
`)
	memlockValueExpected := 4096
	memlockValue, err := FdInfoMemlock(log.NewNopLogger(), data)
	require.NoError(t, err)
	require.Equal(t, memlockValueExpected, memlockValue)
}
