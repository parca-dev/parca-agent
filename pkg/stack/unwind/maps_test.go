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

	"github.com/go-kit/log"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
)

func TestEmptyMappingsWorks(t *testing.T) {
	fpd := NewFramePointerDetector(nil, nil, nil)
	result := ListExecutableMappings(fpd, "", []*procfs.ProcMap{})
	require.Equal(t, ExecutableMappings{}, result)
}

func TestMappingsWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"}}
	result := ListExecutableMappings(fpd, "./my_executable", rawMaps)
	require.Equal(t, ExecutableMappings{
		{StartAddr: 0x0, EndAddr: 0x100, Executable: "./my_executable", mainExec: true},
	}, result)
	require.False(t, result[0].IsSpecial())
}

func TestMappingsWithSplitSectionsWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Write: true}, Pathname: "./my_executable"},
		{StartAddr: 0x200, EndAddr: 0x300, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}
	result := ListExecutableMappings(fpd, "./my_executable", rawMaps)
	require.Equal(t, &ExecutableMapping{LoadAddr: 0x0, StartAddr: 0x200, EndAddr: 0x300, Executable: "./my_executable", mainExec: true}, result[0])
}

func TestMappingsWithJITtedSectionsWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Write: true}, Pathname: "./my_executable"},
		{StartAddr: 0x200, EndAddr: 0x300, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: ""},
	}
	result := ListExecutableMappings(fpd, "./my_executable", rawMaps)
	require.Equal(t, &ExecutableMapping{LoadAddr: 0x0, StartAddr: 0x200, EndAddr: 0x300, Executable: "", mainExec: false}, result[0])
}

func TestMappingsJITSectionDetectionWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Execute: true}},
	}
	result := ListExecutableMappings(fpd, "/my_executable", rawMaps)
	require.True(t, result.HasJITted())
}

func TestMappingsIsNotFileBackedWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Execute: true}},
	}
	result := ListExecutableMappings(fpd, "./my_executable", rawMaps)
	require.False(t, result[0].IsNotFileBacked())
	require.True(t, result[1].IsNotFileBacked())
}

func TestMappingJITDetectionWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "./my_executable"},
		{StartAddr: 0x100, EndAddr: 0x200, Perms: &procfs.ProcMapPermissions{Execute: true}},
	}
	result := ListExecutableMappings(fpd, "./my_executable", rawMaps)
	require.Len(t, result, 2)
	require.False(t, result[0].IsJITted())
	require.True(t, result[1].IsJITted())
}

func TestMappingSpecialSectionDetectionWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "[vdso]"},
	}
	result := ListExecutableMappings(fpd, "exe", rawMaps)
	require.Len(t, result, 1)
	require.True(t, result[0].IsSpecial())
}

func TestMappingJITDumpDetectionWorks(t *testing.T) {
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "/jit-4.dump"},
	}
	result := ListExecutableMappings(fpd, "exe", rawMaps)
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
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	rawMaps := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}

	rawMapsCopy := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libc"},
	}

	hash, err := ListExecutableMappings(fpd, "", rawMaps).Hash()
	require.NoError(t, err)
	hashCopy, err := ListExecutableMappings(fpd, "", rawMapsCopy).Hash()
	require.NoError(t, err)

	// Ensure the hasher has been seeded.
	require.Equal(t, hash, hashCopy)

	rawMapsTypo := []*procfs.ProcMap{
		{StartAddr: 0x0, EndAddr: 0x100, Perms: &procfs.ProcMapPermissions{Read: true}, Pathname: "./my_executable"},
		{StartAddr: 0x300, EndAddr: 0x400, Perms: &procfs.ProcMapPermissions{Execute: true}, Pathname: "libd"}, // <- typo
	}
	mappings, err := ListExecutableMappings(fpd, "", rawMapsTypo)
	require.NoError(t, err)
	hashTypo, err := mappings.Hash()
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

	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	objFilePool := objectfile.NewPool(logger, reg, "", 10, 0)
	cim := runtime.NewCompilerInfoManager(logger, reg, objFilePool)
	fpd := NewFramePointerDetector(logger, reg, cim)

	procs, err := procfs.AllProcs()
	require.NoError(t, err)

	for _, proc := range procs {
		mappings, err := proc.ProcMaps()
		if !errors.Is(err, os.ErrNotExist) {
			require.NoError(t, err)
		}
		if err == nil {
			exe, err := proc.Executable()
			require.NoError(t, err)
			_, err = ListExecutableMappings(fpd, exe, mappings)
			require.NoError(t, err)
		}
	}
}
