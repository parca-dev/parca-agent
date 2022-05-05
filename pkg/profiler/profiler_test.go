// Copyright (c) 2022 The Parca Authors
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

package profiler

import (
	"syscall"
	"testing"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/stretchr/testify/require"
)

// The intent of these tests is to ensure that the BPF library we use,
// (libbpfgo in this case) behaves in the way we expect.

func SetUpBpfProgram(t *testing.T) (*bpf.Module, error) {
	t.Helper()

	m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "parca",
	})
	require.NoError(t, err)

	err = m.BPFLoadObject()
	require.NoError(t, err)

	return m, nil
}

func TestDeleteNonExistentKeyReturnsEnoent(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(countsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Delete should fail as the key doesn't exist.
	err = bpfMap.DeleteKey(unsafe.Pointer(&stackID))
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOENT)
}

func TestDeleteExistentKey(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(countsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Insert some element that will be later deleted.
	value := []byte{'a'}
	err = bpfMap.Update(unsafe.Pointer(&stackID), unsafe.Pointer(&value[0]))
	require.NoError(t, err)

	// Delete should work.
	err = bpfMap.DeleteKey(unsafe.Pointer(&stackID))
	require.NoError(t, err)
}

func TestGetValueAndDeleteBatchWithEmptyMap(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(countsMapName)
	require.NoError(t, err)

	keys := make([]stackCountKey, bpfMap.GetMaxEntries())
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := bpfMap.GetMaxEntries()
	values, err := bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)
	require.NoError(t, err)
	require.Equal(t, 0, len(values))
}

func TestGetValueAndDeleteBatchFewerElementsThanCount(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(countsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Insert some element that will be later deleted.
	value := []byte{'a'}
	err = bpfMap.Update(unsafe.Pointer(&stackID), unsafe.Pointer(&value[0]))
	require.NoError(t, err)

	// Request more elements than we have, this should return and delete everything.
	keys := make([]stackCountKey, bpfMap.GetMaxEntries())
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := bpfMap.GetMaxEntries()
	values, err := bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)
	require.NoError(t, err)
	require.Equal(t, 1, len(values))
}

func TestGetValueAndDeleteBatchExactElements(t *testing.T) {
	m, err := SetUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)
	bpfMap, err := m.GetMap(countsMapName)
	require.NoError(t, err)

	stackID := int32(1234)

	// Insert some element that will be later deleted.
	value := []byte{'a'}
	err = bpfMap.Update(unsafe.Pointer(&stackID), unsafe.Pointer(&value[0]))
	require.NoError(t, err)

	// Request exactly the elements we have.
	keys := make([]stackCountKey, 1)
	countKeysPtr := unsafe.Pointer(&keys[0])
	nextCountKey := uintptr(1)
	batchSize := uint32(1)
	values, err := bpfMap.GetValueAndDeleteBatch(countKeysPtr, nil, unsafe.Pointer(&nextCountKey), batchSize)
	require.NoError(t, err)
	require.Equal(t, 1, len(values))
}
