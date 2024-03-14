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
	"debug/elf"
	"encoding/gob"
	"errors"
	"fmt"
	"hash/maphash"
	"os"
	"strings"

	"github.com/prometheus/procfs"
)

// ExecutableMapping represents an executable memory mapping.
type ExecutableMapping struct {
	LoadAddr   uint64
	StartAddr  uint64
	EndAddr    uint64
	Executable string

	mainExec bool
	fpdr     FramePointerDetectionResult
}

// IsMainObject returns whether this executable is the "main executable".
// which triggered the loading of all the other mappings.
//
// We care about this because if Linux ASLR is enabled, we have to
// modify the loaded addresses for the main object.
func (pm *ExecutableMapping) IsMainObject() bool {
	return pm.mainExec
}

// IsJITted returns whether an executable mapping is JITed or not.
// The detection is done by checking if the executable mapping is
// not backed by a file.
//
// We don't check for the writeable flag as `mprotect(2)` may be
// called to make it r+w only.
func (pm *ExecutableMapping) IsJITted() bool {
	return pm.Executable == ""
}

// IsJITDump returns whether the mapping looks like a jitdump[0] file.
//
// [0]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jitdump-specification.txt
func (pm *ExecutableMapping) IsJITDump() bool {
	return strings.Contains(pm.Executable, "jit") && strings.HasSuffix(pm.Executable, ".dump")
}

// IsNotFileBacked returns whether the mapping is not backed by a
// file, such as JIT or vDSO sections.
func (pm *ExecutableMapping) IsNotFileBacked() bool {
	return pm.IsJITted() || pm.IsSpecial()
}

// IsSpecial returns whether the file mapping is a "special" region,
// such as the mappings for vDSOs `[vdso]` and others.
func (pm *ExecutableMapping) IsSpecial() bool {
	return len(pm.Executable) > 0 && pm.Executable[0] == '['
}

// HasFramePointers returns whether the mapping has frame pointers.
func (pm *ExecutableMapping) HasFramePointers() bool {
	if pm.fpdr.OnlyMainExecutable {
		return pm.mainExec
	}

	return pm.fpdr.AllMappings
}

func (pm *ExecutableMapping) String() string {
	return fmt.Sprintf("ExecutableMapping {LoadAddr: 0x%x, StartAddr: 0x%x, EndAddr: 0x%x, Executable:%s}", pm.LoadAddr, pm.StartAddr, pm.EndAddr, pm.Executable)
}

type ExecutableMappings []*ExecutableMapping

// ExecutableMappings returns the executable memory mappings with the appropriate
// loaded base address set for non-JIT code.
//
// The reason why we need to find the loaded base address is that ELF executables
// aren't typically loaded in one large executable section, but split in several
// mappings. For example, the .rodata section, as well as .eh_frame might go in
// sections without executable permissions, as they aren't needed.
//
// Note: jitdump files are typically executable but are excluded from the results.
func ListExecutableMappings(fpd *FramePointerDetector, exe string, rawMappings []*procfs.ProcMap) (ExecutableMappings, error) {
	framePointerDetection, err := fpd.HasFramePointers(exe) // nolint:contextcheck
	if err != nil {
		// It might not exist as reading procfs is racy. If the executable has no symbols
		// that we use as a heuristic to detect whether it has frame pointers or not,
		// we assume it does not and that we should generate the unwind information.
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, elf.ErrNoSymbols) {
			return nil, fmt.Errorf("failed to detect frame pointers: %w", err)
		}
	}

	result := make([]*ExecutableMapping, 0, executableMappingCount(rawMappings))
	for idx, rawMapping := range rawMappings {
		if rawMapping.Perms.Execute {
			var loadAddr uint64
			// We need the load base address for stack unwinding with DWARF
			// information. We don't know of any runtimes that emit said unwind
			// information for JITed code, so we set it to zero.
			if rawMappings[idx].Pathname != "" {
				for revIdx := idx; revIdx >= 0; revIdx-- {
					if rawMappings[revIdx].Pathname != rawMappings[idx].Pathname {
						break
					}
					loadAddr = uint64(rawMappings[revIdx].StartAddr)
				}
			}

			mapping := ExecutableMapping{
				LoadAddr:   loadAddr,
				StartAddr:  uint64(rawMapping.StartAddr),
				EndAddr:    uint64(rawMapping.EndAddr),
				Executable: rawMapping.Pathname,
				mainExec:   rawMapping.Pathname == exe,
				fpdr:       framePointerDetection,
			}

			// Exclude jitdump from the results because we don't need these mappings.
			// If in the future we add support for unwinding via the information present
			// in these files, we can link this information to the corresponding code
			// sections generated by the JIT.
			if mapping.IsJITDump() {
				continue
			}
			result = append(result, &mapping)
		}
	}

	return result, nil
}

// HasJITted returns if there's at least one JIT'ed mapping.
func (pm ExecutableMappings) HasJITted() bool {
	for _, execMapping := range pm {
		if execMapping.IsJITted() {
			return true
		}
	}
	return false
}

var seed = maphash.MakeSeed()

// Hash produces a summary of the executable mappings.
func (pm ExecutableMappings) Hash() (uint64, error) {
	var h maphash.Hash
	h.SetSeed(seed)
	encoder := gob.NewEncoder(&h)
	err := encoder.Encode(pm)
	if err != nil {
		return 0, fmt.Errorf("encode error: %w", err)
	}
	return h.Sum64(), nil
}

// executableMappingCount returns the number of executable mappings
// in the passed `rawMappings`.
func executableMappingCount(rawMappings []*procfs.ProcMap) uint {
	var executableMappingCount uint
	for _, rawMapping := range rawMappings {
		if rawMapping.Perms.Execute {
			executableMappingCount += 1
		}
	}
	return executableMappingCount
}
