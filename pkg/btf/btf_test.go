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

package btf

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/stretchr/testify/require"

	embed "github.com/parca-dev/parca-agent"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

const (
	pidMapName = "pid_map"
)

// The intent of these tests is to ensure that BTF relocations behaves the
// way we expect.
//
// We also use them to ensure that different kernel versions load our
// BPF program.
func setUpBpfProgram(t *testing.T) (*bpf.Module, error) {
	t.Helper()

	bpfObj, err := embed.BPFBundleTest.ReadFile("dist/btf/test.bpf.o")
	require.NoError(t, err)

	m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "parca-btf-test",
	})
	require.NoError(t, err)

	memLock := uint64(1200 * 1024 * 1024) // ~1.2GiB
	_, err = profiler.BumpMemlock(memLock, memLock)
	require.NoError(t, err)

	err = m.BPFLoadObject()
	require.NoError(t, err)

	return m, nil
}

func TestDeleteNonExistentKeyReturnsEnoent(t *testing.T) {
	m, err := setUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)

	bpfMap, err := m.GetMap(pidMapName)
	require.NoError(t, err)

	pid := os.Getpid()

	zero := uint32(0)
	value, err := bpfMap.GetValue(unsafe.Pointer(&zero))
	require.Error(t, err)

	var btfPid int
	err = binary.Read(bytes.NewBuffer(value), binary.LittleEndian, &btfPid)
	require.NoError(t, err)

	require.Equal(t, pid, btfPid)
}
