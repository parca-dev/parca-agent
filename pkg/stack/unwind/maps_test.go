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
//

package unwind

import (
	"errors"
	"os"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
)

func TestEmptyMappingsWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{}
	result := ListExecutableMappings(rawMaps)
	require.Equal(t, ExecutableMappings{}, result)
}

func TestMappingsWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"}}
	result := ListExecutableMappings(rawMaps)
	require.Equal(t, ExecutableMappings{
		{StartAddr: 0x0, EndAddr: 0x100, Executable: "./my_executable", mainExec: true},
	}, result)
	require.False(t, result[0].IsSpecial())
}

func TestMappingsWithSplitSectionsWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Write: true}, Pathname: "./my_executable"},
		{StartAddr: 0x200, EndAddr: 0x300, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}
	result := ListExecutableMappings(rawMaps)
	require.Equal(t, &ExecutableMapping{LoadAddr: 0x0, StartAddr: 0x200, EndAddr: 0x300, Executable: "./my_executable", mainExec: true}, result[0])
}

func TestMappingsWithJITtedSectionsWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Write: true}, Pathname: "./my_executable"},
		{StartAddr: 0x200, EndAddr: 0x300, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: ""},
	}
	result := ListExecutableMappings(rawMaps)
	require.Equal(t, &ExecutableMapping{LoadAddr: 0x0, StartAddr: 0x200, EndAddr: 0x300, Executable: "", mainExec: true}, result[0])
}

func TestMappingsJITSectionDetectionWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Execute: true}},
	}
	result := ListExecutableMappings(rawMaps)
	require.True(t, result.HasJITted())
}

func TestMappingsIsNotFileBackedWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Execute: true}},
	}
	result := ListExecutableMappings(rawMaps)
	require.False(t, result[0].IsNotFileBacked())
	require.True(t, result[1].IsNotFileBacked())
}

func TestMappingJITDetectionWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Execute: true}},
	}
	result := ListExecutableMappings(rawMaps)
	require.Len(t, result, 2)
	require.False(t, result[0].IsJITted())
	require.True(t, result[1].IsJITted())
}

func TestMappingSpecialSectionDetectionWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "[vdso]"},
	}
	result := ListExecutableMappings(rawMaps)
	require.Len(t, result, 1)
	require.True(t, result[0].IsSpecial())
}

func TestMappingJITDumpDetectionWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "/jit-4.dump"},
	}
	result := ListExecutableMappings(rawMaps)
	require.Empty(t, result)
}

func TestExecutableMappingCountWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{}
	require.Equal(t, uint(0), executableMappingCount(rawMaps))

	rawMaps = []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Write: true}, Pathname: "./my_executable"},
		{StartAddr: 0x200, EndAddr: 0x300, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}

	require.Equal(t, uint(2), executableMappingCount(rawMaps))
}

func TestExecutableHashWorks(t *testing.T) {
	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}

	rawMapsCopy := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}

	hash, err := ListExecutableMappings(rawMaps).Hash()
	require.NoError(t, err)
	hashCopy, err := ListExecutableMappings(rawMapsCopy).Hash()
	require.NoError(t, err)

	// Ensure the hasher has been seeded.
	require.Equal(t, hash, hashCopy)

	rawMapsTypo := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libd"}, // <- typo
	}
	hashTypo, err := ListExecutableMappings(rawMapsTypo).Hash()
	require.NoError(t, err)

	// Silly test but better be safe than sorry.
	require.NotEqual(t, hash, hashTypo)
}

// Not to be run normally, but helpful to find behavior that
// might not be covered by unittests.
func TestAllProcesses(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root")
	}

	procs, err := procfs.AllProcs()
	require.NoError(t, err)

	for _, proc := range procs {
		mappings, err := proc.ProcMaps()
		if !errors.Is(err, os.ErrNotExist) {
			require.NoError(t, err)
		}
		if err == nil {
			_ = ListExecutableMappings(mappings)
		}
	}
}
