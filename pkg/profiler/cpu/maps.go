// Copyright 2022 The Parca Authors
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

package cpu

import "C"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/procfs"
	"golang.org/x/exp/constraints"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/executable"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

const (
	debugPIDsMapName        = "debug_pids"
	stackCountsMapName      = "stack_counts"
	stackTracesMapName      = "stack_traces"
	unwindShardsMapName     = "unwind_shards"
	dwarfStackTracesMapName = "dwarf_stack_traces"
	unwindTablesMapName     = "unwind_tables"
	processInfoMapName      = "process_info"
	programsMapName         = "programs"

	// With the current compact rows, the max items we can store in the kernels
	// we have tested is 262k per map, which we rounded it down to 250k.
	unwindTableMaxEntries = 50         // How many unwind table shards we have.
	maxUnwindTableSize    = 250 * 1000 // Always needs to be sync with MAX_UNWIND_TABLE_SIZE in the BPF program.
	maxMappingsPerProcess = 120        // Always need to be in sync with MAX_MAPPINGS_PER_PROCESS.
	/*
		TODO: once we generate the bindings automatically, remove this.

		typedef struct mapping {
			u64 load_address;
			u64 begin;
			u64 end;
			u64 executable_id;
			u64 type;
		} mapping_t;

		typedef struct {
			u64 is_jit_compiler;
			u64 len;
			mapping_t mappings[MAX_MAPPINGS_PER_PROCESS];
		} process_info_t;
	*/
	procInfoSizeBytes = 8 + 8 + (maxMappingsPerProcess * 8 * 5)
)

var (
	errMissing                   = errors.New("missing stack trace")
	errUnwindFailed              = errors.New("stack ID is 0, probably stack unwinding failed")
	errUnrecoverable             = errors.New("unrecoverable error")
	errTooManyExecutableMappings = errors.New("too many executable mappings")
)

type bpfMaps struct {
	logger log.Logger

	module    *bpf.Module
	byteOrder binary.ByteOrder

	debugPIDs *bpf.BPFMap

	stackCounts      *bpf.BPFMap
	stackTraces      *bpf.BPFMap
	dwarfStackTraces *bpf.BPFMap
	processInfo      *bpf.BPFMap

	unwindShards *bpf.BPFMap
	unwindTables *bpf.BPFMap
	programs     *bpf.BPFMap

	// unwind stuff 🔬
	processCache burrow.Cache
	procInfoBuf  *bytes.Buffer

	buildIDMapping map[string]uint64
	//	globalView []{shard_id:, [all the ranges it contains]}
	// which shard we are on
	shardIndex    uint64
	executableID  uint64
	unwindInfoBuf *bytes.Buffer
	// Account where we are within a shard
	lowIndex  uint64
	highIndex uint64
	// Other stats
	totalEntries       uint64
	uniqueMappings     uint64
	referencedMappings uint64
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func initializeMaps(logger log.Logger, m *bpf.Module, byteOrder binary.ByteOrder) (*bpfMaps, error) {
	if m == nil {
		return nil, fmt.Errorf("nil module")
	}

	procInfoArray := make([]byte, 0, procInfoSizeBytes)
	unwindInfoArray := make([]byte, 0, maxUnwindTableSize*unsafe.Sizeof(unwind.CompactUnwindTableRow{}))

	maps := &bpfMaps{
		logger:         log.With(logger, "component", "maps"),
		module:         m,
		byteOrder:      byteOrder,
		processCache:   burrow.New(),
		procInfoBuf:    bytes.NewBuffer(procInfoArray),
		unwindInfoBuf:  bytes.NewBuffer(unwindInfoArray),
		buildIDMapping: make(map[string]uint64),
	}

	if err := maps.resetInFlightBuffer(); err != nil {
		level.Error(logger).Log("msg", "resetInFlightBuffer failed", "err", err)
	}

	return maps, nil
}

// adjustMapSizes updates unwinding maps' maximum size. By default, it tries to keep it as low
// as possible.
//
// Note: It must be called before `BPFLoadObject()`.
func (m *bpfMaps) adjustMapSizes(enableDWARFUnwinding bool) error {
	unwindTables, err := m.module.GetMap(unwindTablesMapName)
	if err != nil {
		return fmt.Errorf("get unwind tables map: %w", err)
	}

	// Adjust unwind tables size.
	if enableDWARFUnwinding {
		sizeBefore := unwindTables.GetMaxEntries()
		if err := unwindTables.Resize(unwindTableMaxEntries); err != nil {
			return fmt.Errorf("resize unwind tables map from %d to %d elements: %w", sizeBefore, unwindTableMaxEntries, err)
		}
	}

	return nil
}

func (m *bpfMaps) create() error {
	debugPIDs, err := m.module.GetMap(debugPIDsMapName)
	if err != nil {
		return fmt.Errorf("get debug pids map: %w", err)
	}

	stackCounts, err := m.module.GetMap(stackCountsMapName)
	if err != nil {
		return fmt.Errorf("get counts map: %w", err)
	}

	stackTraces, err := m.module.GetMap(stackTracesMapName)
	if err != nil {
		return fmt.Errorf("get stack traces map: %w", err)
	}

	unwindShards, err := m.module.GetMap(unwindShardsMapName)
	if err != nil {
		return fmt.Errorf("get unwind shards map: %w", err)
	}

	unwindTables, err := m.module.GetMap(unwindTablesMapName)
	if err != nil {
		return fmt.Errorf("get unwind tables map: %w", err)
	}

	dwarfStackTraces, err := m.module.GetMap(dwarfStackTracesMapName)
	if err != nil {
		return fmt.Errorf("get dwarf stack traces map: %w", err)
	}

	processInfo, err := m.module.GetMap(processInfoMapName)
	if err != nil {
		return fmt.Errorf("get process info map: %w", err)
	}

	m.debugPIDs = debugPIDs
	m.stackCounts = stackCounts
	m.stackTraces = stackTraces
	m.unwindShards = unwindShards
	m.unwindTables = unwindTables
	m.dwarfStackTraces = dwarfStackTraces
	m.processInfo = processInfo

	return nil
}

func (m *bpfMaps) setDebugPIDs(pids []int) error {
	// Clean up old debug pids.
	it := m.debugPIDs.Iterator()
	var prev []byte = nil
	for it.Next() {
		if prev != nil {
			err := m.debugPIDs.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete debug pid: %w", err)
			}
		}

		key := it.Key()
		prev = make([]byte, len(key))
		copy(prev, key)
	}
	if prev != nil {
		err := m.debugPIDs.DeleteKey(unsafe.Pointer(&prev[0]))
		if err != nil {
			return fmt.Errorf("failed to delete debug pid: %w", err)
		}
	}
	// Set new debug pids.
	one := uint8(1)
	for _, pid := range pids {
		pid := int32(pid)
		if err := m.debugPIDs.Update(unsafe.Pointer(&pid), unsafe.Pointer(&one)); err != nil {
			return fmt.Errorf("failure setting debug pid %d: %w", pid, err)
		}
	}
	return nil
}

// readUserStack reads the user stack trace from the stacktraces ebpf map into the given buffer.
func (m *bpfMaps) readUserStack(userStackID int32, stack *combinedStack) error {
	if userStackID == 0 {
		return errUnwindFailed
	}

	stackBytes, err := m.stackTraces.GetValue(unsafe.Pointer(&userStackID))
	if err != nil {
		return fmt.Errorf("read user stack trace, %v: %w", err, errMissing)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, stack[:stackDepth]); err != nil {
		return fmt.Errorf("read user stack bytes, %s: %w", err, errUnrecoverable)
	}

	return nil
}

// readUserStackWithDwarf reads the DWARF walked user stack traces into the given buffer.
func (m *bpfMaps) readUserStackWithDwarf(userStackID int32, stack *combinedStack) error {
	if userStackID == 0 {
		return errUnwindFailed
	}

	type dwarfStacktrace struct {
		Len   uint64
		Addrs [stackDepth]uint64
	}

	stackBytes, err := m.dwarfStackTraces.GetValue(unsafe.Pointer(&userStackID))
	if err != nil {
		return fmt.Errorf("read user stack trace, %v: %w", err, errMissing)
	}

	var dwarfStack dwarfStacktrace
	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, &dwarfStack); err != nil {
		return fmt.Errorf("read user stack bytes, %s: %w", err, errUnrecoverable)
	}

	userStack := stack[:stackDepth]

	for i, addr := range dwarfStack.Addrs {
		if i >= stackDepth || i >= int(dwarfStack.Len) || addr == 0 {
			break
		}
		userStack[i] = addr
	}

	return nil
}

// readKernelStack reads the kernel stack trace from the stacktraces ebpf map into the given buffer.
func (m *bpfMaps) readKernelStack(kernelStackID int32, stack *combinedStack) error {
	if kernelStackID == 0 {
		return errUnwindFailed
	}

	stackBytes, err := m.stackTraces.GetValue(unsafe.Pointer(&kernelStackID))
	if err != nil {
		return fmt.Errorf("read kernel stack trace, %v: %w", err, errMissing)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, stack[stackDepth:]); err != nil {
		return fmt.Errorf("read kernel stack bytes, %s: %w", err, errUnrecoverable)
	}

	return nil
}

// readStackCount reads the value of the given key from the counts ebpf map.
func (m *bpfMaps) readStackCount(keyBytes []byte) (uint64, error) {
	valueBytes, err := m.stackCounts.GetValue(unsafe.Pointer(&keyBytes[0]))
	if err != nil {
		return 0, fmt.Errorf("get count value: %w", err)
	}
	return m.byteOrder.Uint64(valueBytes), nil
}

func (m *bpfMaps) clean() error {
	// BPF iterators need the previous value to iterate to the next, so we
	// can only delete the "previous" item once we've already iterated to
	// the next.

	// stackTraces
	{
		it := m.stackTraces.Iterator()
		var prev []byte = nil
		for it.Next() {
			if prev != nil {
				err := m.stackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
				if err != nil {
					return fmt.Errorf("failed to delete stack trace: %w", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := m.stackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete stack trace: %w", err)
			}
		}
	}

	// dwarfStackTraces
	{
		it := m.dwarfStackTraces.Iterator()
		var prev []byte = nil
		for it.Next() {
			if prev != nil {
				err := m.dwarfStackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
				if err != nil {
					return fmt.Errorf("failed to delete dwarf stack trace: %w", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := m.dwarfStackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete dwarf tack trace: %w", err)
			}
		}
	}

	// stackCounts
	{
		it := m.stackCounts.Iterator()
		var prev []byte = nil
		for it.Next() {
			if prev != nil {
				err := m.stackCounts.DeleteKey(unsafe.Pointer(&prev[0]))
				if err != nil {
					return fmt.Errorf("failed to delete count: %w", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := m.stackCounts.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete count: %w", err)
			}
		}
	}

	return nil
}

func (m *bpfMaps) cleanProcessInfo() error {
	// BPF iterators need the previous value to iterate to the next, so we
	// can only delete the "previous" item once we've already iterated to
	// the next.

	// processInfo
	{
		it := m.processInfo.Iterator()
		var prev []byte = nil
		for it.Next() {
			if prev != nil {
				err := m.processInfo.DeleteKey(unsafe.Pointer(&prev[0]))
				if err != nil {
					return fmt.Errorf("failed to delete stack trace: %w", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := m.processInfo.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete stack trace: %w", err)
			}
		}
	}
	return nil
}

func (m *bpfMaps) cleanShardInfo() error {
	// BPF iterators need the previous value to iterate to the next, so we
	// can only delete the "previous" item once we've already iterated to
	// the next.

	// unwindShards
	{
		it := m.unwindShards.Iterator()
		var prev []byte = nil
		for it.Next() {
			if prev != nil {
				err := m.unwindShards.DeleteKey(unsafe.Pointer(&prev[0]))
				if err != nil {
					return fmt.Errorf("failed to delete stack trace: %w", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := m.unwindShards.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete stack trace: %w", err)
			}
		}
	}
	return nil
}

func (m *bpfMaps) resetProcInfoBuffer() error {
	// Set len to zero.
	m.procInfoBuf.Reset()

	// Zero it.
	zero := byte(0)
	// TODO(javierhonduco): This is a waste of allocations and CPU cycles,
	// perhaps this can be optimized.
	for i := 0; i < procInfoSizeBytes; i++ {
		if err := binary.Write(m.procInfoBuf, m.byteOrder, zero); err != nil {
			return fmt.Errorf("failed write zeroes to resetProcInfoBuffer: %w", err)
		}
	}

	// Set len to zero.
	m.procInfoBuf.Reset()

	return nil
}

// 1. Find executable sections
// 2. For each section, generate compact table
// 3. Add table to maps
// 4. Add map metadata to process
func (m *bpfMaps) addUnwindTableForProcess(pid int) error {
	// TODO(javierhonduco): the current caching schema doesn't have any eviction policy,
	// so memory might grow linear to the number of unique seen processes.
	//
	// Some other shortcomings:
	//	- if evicting, we should add some random jitter to ensure that the unwind tables
	// aren't built in the same short window of time causing a big resource spike.
	//	- perhaps we could cache based on `start_at` (but parsing this file properly
	// is challenging...).
	//  - executable mappings can change, think `ldopen`, or JITs. We don't account for this
	// just yet.
	//  - PIDs can be recycled.
	if _, exists := m.processCache.GetIfPresent(pid); exists {
		level.Debug(m.logger).Log("msg", "process already cached", "pid", pid)
		return nil
	}

	proc, err := procfs.NewProc(pid)
	if err != nil {
		return err
	}

	mappings, err := proc.ProcMaps()
	if err != nil {
		return err
	}

	executableMappings := unwind.ListExecutableMappings(mappings)
	if err := m.resetProcInfoBuffer(); err != nil {
		level.Error(m.logger).Log("msg", "resetProcInfoBuffer failed", "err", err)
	}

	// Important: the below *must* be called before setUnwindTable.
	// .is_jit_compiler
	var isJitCompiler uint64
	if executableMappings.HasJitted() {
		isJitCompiler = 1
	}
	if err := binary.Write(m.procInfoBuf, m.byteOrder, isJitCompiler); err != nil {
		return fmt.Errorf("write proc_info .is_jit_compiler bytes: %w", err)
	}

	if len(executableMappings) >= maxMappingsPerProcess {
		return errTooManyExecutableMappings
	}

	// .len
	if err := binary.Write(m.procInfoBuf, m.byteOrder, uint64(len(executableMappings))); err != nil {
		return fmt.Errorf("write proc_info .len bytes: %w", err)
	}

	for _, executableMapping := range executableMappings {
		if err := m.setUnwindTableForMapping(pid, executableMapping, m.procInfoBuf); err != nil {
			return fmt.Errorf("setUnwindTableForMapping failed: %w", err)
		}
	}

	if err := m.processInfo.Update(unsafe.Pointer(&pid), unsafe.Pointer(&m.procInfoBuf.Bytes()[0])); err != nil {
		return fmt.Errorf("update processInfo: %w", err)
	}

	m.processCache.Put(pid, struct{}{})
	return nil
}

// generateCompactUnwindTable produces the compact unwidn table for a given
// executable.
func (m *bpfMaps) generateCompactUnwindTable(fullExecutablePath string, mapping *unwind.ExecutableMapping) (unwind.CompactUnwindTable, uint64, uint64, error) {
	var minCoveredPc uint64
	var maxCoveredPc uint64
	var ut unwind.CompactUnwindTable

	// Fetch FDEs.
	fdes, err := unwind.ReadFDEs(fullExecutablePath)
	if err != nil {
		return ut, 0, 0, err
	}

	// Sort them, as this will ensure that the generated table
	// is also sorted. Sorting fewer elements will be faster.
	sort.Sort(fdes)
	minCoveredPc = fdes[0].Begin()
	maxCoveredPc = fdes[len(fdes)-1].End()

	// Generate the compact unwind table.
	ut, err = unwind.BuildCompactUnwindTable(fdes)
	if err != nil {
		return ut, 0, 0, err
	}

	// This should not be necessary, as per the sorting above, but
	// just in case :).
	sort.Sort(ut)

	// Now we have a full compact unwind table that we have to split in different BPF maps.
	level.Debug(m.logger).Log("msg", "found unwind entries", "executable", mapping.Executable, "len", len(ut), "low pc", fmt.Sprintf("%x", minCoveredPc), "high pc", fmt.Sprintf("%x", maxCoveredPc))

	return ut, minCoveredPc, maxCoveredPc, nil
}

// writeUnwindTableRow writes a compact unwind table row to the provided buffer.
//
// Note: we are writing field by field to avoid extra allocations and CPU spent in
// the reflection code paths in `binary.Write`.
func (m *bpfMaps) writeUnwindTableRow(buffer *bytes.Buffer, row unwind.CompactUnwindTableRow) error {
	// .pc
	if err := binary.Write(buffer, m.byteOrder, row.Pc()); err != nil {
		return fmt.Errorf("write unwind table .pc bytes: %w", err)
	}

	// .__reserved_do_not_use
	if err := binary.Write(buffer, m.byteOrder, row.ReservedDoNotUse()); err != nil {
		return fmt.Errorf("write unwind table __reserved_do_not_use bytes: %w", err)
	}

	// .cfa_type
	if err := binary.Write(buffer, m.byteOrder, row.CfaType()); err != nil {
		return fmt.Errorf("write unwind table cfa_type bytes: %w", err)
	}

	// .rbp_type
	if err := binary.Write(buffer, m.byteOrder, row.RbpType()); err != nil {
		return fmt.Errorf("write unwind table rbp_type bytes: %w", err)
	}

	// .cfa_offset
	if err := binary.Write(buffer, m.byteOrder, row.CfaOffset()); err != nil {
		return fmt.Errorf("write unwind table cfa_offset bytes: %w", err)
	}

	// .rbp_offset
	if err := binary.Write(buffer, m.byteOrder, row.RbpOffset()); err != nil {
		return fmt.Errorf("write unwind table rbp_offset bytes: %w", err)
	}

	return nil
}

// writeMapping writes the memory mapping information to the provided buffer.
//
// Note: we write field by field to avoid the expensive reflection code paths
// when writing structs using `binary.Write`.
func (m *bpfMaps) writeMapping(procInfoBuf *bytes.Buffer, loadAddress, startAddr, endAddr, executableID, type_ uint64) error {
	// .load_address
	if err := binary.Write(procInfoBuf, m.byteOrder, loadAddress); err != nil {
		return fmt.Errorf("write mappings .load_address bytes: %w", err)
	}
	// .begin
	if err := binary.Write(procInfoBuf, m.byteOrder, startAddr); err != nil {
		return fmt.Errorf("write mappings .begin bytes: %w", err)
	}
	// .end
	if err := binary.Write(procInfoBuf, m.byteOrder, endAddr); err != nil {
		return fmt.Errorf("write mappings .end bytes: %w", err)
	}
	// .executable_id
	if err := binary.Write(procInfoBuf, m.byteOrder, executableID); err != nil {
		return fmt.Errorf("write proc info .executable_id bytes: %w", err)
	}
	// .type
	if err := binary.Write(procInfoBuf, m.byteOrder, type_); err != nil {
		return fmt.Errorf("write proc info .type bytes: %w", err)
	}

	return nil
}

// mappingID returns the internal identifier for a memory mapping.
//
// It will either return the already produced ID or generate a new
// one while indicating whether it was already seen or not.
//
// This allows us to reuse the unwind tables for the mappings we
// see.
func (m *bpfMaps) mappingID(buildID string) (uint64, bool) {
	_, alreadySeenMapping := m.buildIDMapping[buildID]
	if alreadySeenMapping {
		level.Debug(m.logger).Log("msg", "mapping caching, seen before", "buildID", buildID)
		m.referencedMappings += 1
	} else {
		level.Debug(m.logger).Log("msg", "mapping caching, new", "buildID", buildID)
		m.buildIDMapping[buildID] = m.executableID
	}

	return m.buildIDMapping[buildID], alreadySeenMapping
}

// resetInFlightBuffer zeroes and resets the length of the
// in-flight shard.
func (m *bpfMaps) resetInFlightBuffer() error {
	// Reset first
	m.unwindInfoBuf.Reset()

	// Zero it.
	zero := uint64(0)
	// This is a waste of CPU (+allocs).
	for i := 0; i < maxUnwindTableSize; i++ {
		// .pc.
		if err := binary.Write(m.unwindInfoBuf, m.byteOrder, zero); err != nil {
			return fmt.Errorf("write unwindInfoBuf .pc bytes: %w", err)
		}
		// rest of the fields.
		if err := binary.Write(m.unwindInfoBuf, m.byteOrder, zero); err != nil {
			return fmt.Errorf("write unwindInfoBuf <rest> bytes: %w", err)
		}
	}

	// Reset again.
	m.unwindInfoBuf.Reset()
	return nil
}

// PersistUnwindTable writes the current in-flight, writable shard
// to the corresponding BPF map's shard.
//
// Note: as of now, this must be called in two situations:
//   - In the callsite, once we are done with generating the unwind
//     tables.
//   - Whenever the current in-flight shard is full, before we wipe
//     it and start reusing it.
func (m *bpfMaps) PersistUnwindTable() error {
	totalRows := uintptr(m.unwindInfoBuf.Len()) / unsafe.Sizeof(unwind.CompactUnwindTableRow{})
	if totalRows > maxUnwindTableSize {
		panic("totalRows > maxUnwindTableSize should never happen")
	}
	level.Debug(m.logger).Log("msg", "PersistUnwindTable called", "live unwind rows", totalRows)

	if totalRows == 0 {
		return nil
	}

	shardIndex := m.shardIndex

	err := m.unwindTables.Update(unsafe.Pointer(&shardIndex), unsafe.Pointer(&m.unwindInfoBuf.Bytes()[0]))
	if err != nil {
		if errors.Is(err, syscall.E2BIG) {
			if err := m.resetUnwindState(); err != nil {
				level.Error(m.logger).Log("msg", "resetUnwindState failed", "err", err)
				return err
			}
			return nil
		}
		return fmt.Errorf("update unwind tables: %w", err)
	}

	return nil
}

func (m *bpfMaps) resetUnwindState() error {
	m.processCache = burrow.New()
	m.buildIDMapping = make(map[string]uint64)
	m.shardIndex = 0
	m.executableID = 0
	if err := m.resetInFlightBuffer(); err != nil {
		level.Error(m.logger).Log("msg", "resetInFlightBuffer failed", "err", err)
	}

	m.lowIndex = 0
	m.highIndex = 0
	// Other stats
	m.totalEntries = 0
	m.uniqueMappings = 0
	m.referencedMappings = 0

	// TODO(javierhonduco): Ensure we reset everything, including:
	// - process
	// - shards
	// - heap
	// - stats
	// etc.
	if err := m.cleanProcessInfo(); err != nil {
		level.Error(m.logger).Log("msg", "cleanProcessInfo failed", "err", err)
		return err
	}
	if err := m.cleanShardInfo(); err != nil {
		level.Error(m.logger).Log("msg", "cleanShardInfo failed", "err", err)
		return err
	}
	if err := m.clean(); err != nil {
		level.Error(m.logger).Log("msg", "clean failed", "err", err)
		return err
	}

	return nil
}

// availableEntries returns how many entries we have left
// in the in-flight shard.
func (m *bpfMaps) availableEntries() uint64 {
	return maxUnwindTableSize - m.highIndex
}

// assertInvariants checks that some invariants that should
// always be true during the execution of the program are held.
func (m *bpfMaps) assertInvariants() {
	if m.highIndex > maxUnwindTableSize {
		panic("m.highIndex > 250k, this should never happen")
	}
	if uintptr(m.unwindInfoBuf.Len())/unsafe.Sizeof(unwind.CompactUnwindTableRow{}) >= maxUnwindTableSize {
		panic("unwindInfoBuf has more than 250k entries")
	}
	if m.availableEntries() == 0 {
		panic("no space left in the in-flight shard, this should never happen")
	}
}

// setUnwindTableForMapping sets all the necessary metadata and unwind tables, if needed
// to make DWARF unwinding work, such as:
//
//   - Continue appending information to the executable mapping information for a process.
//   - Add mapping information.
//   - If unwind table is already present, we are done here, otherwise, we generate the
//     unwind table for this executable and write to the in-flight shard.
//
// Notes:
// -
// - This function is *not* safe to be called concurrently.
func (m *bpfMaps) setUnwindTableForMapping(pid int, mapping *unwind.ExecutableMapping, procInfoBuf *bytes.Buffer) error {
	level.Debug(m.logger).Log("msg", "setUnwindTable called", "shards", m.shardIndex, "max shards", unwindTableMaxEntries, "sum of unwind rows", m.totalEntries)

	// Deal with mappings that are not filed backed. They don't have unwind
	// information.
	if mapping.IsNotFileBacked() {
		var type_ uint64
		if mapping.IsJitted() {
			level.Debug(m.logger).Log("msg", "jit section", "pid", pid)
			type_ = 1
		}
		if mapping.IsSpecial() {
			level.Debug(m.logger).Log("msg", "special section", "pid", pid)
			type_ = 2
		}

		err := m.writeMapping(procInfoBuf, mapping.LoadAddr, mapping.StartAddr, mapping.EndAddr, uint64(0), type_)
		if err != nil {
			return fmt.Errorf("writing mappings failed with %w", err)
		}
		return nil
	}

	// Deal with mappings that are backed by a file and might contain unwind
	// information.
	fullExecutablePath := path.Join("/proc/", fmt.Sprintf("%d", pid), "/root/", mapping.Executable)

	elfFile, err := elf.Open(fullExecutablePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("elf.Open failed: %w", err)
	}
	buildID, err := buildid.BuildID(&buildid.ElfFile{File: elfFile, Path: fullExecutablePath})
	if err != nil {
		return fmt.Errorf("BuildID failed %s: %w", fullExecutablePath, err)
	}

	// Find the adjusted load address.
	aslrElegible := executable.IsASLRElegibleElf(elfFile)

	adjustedLoadAddress := uint64(0)
	if mapping.IsMainObject() {
		level.Debug(m.logger).Log("msg", "dealing with main object", "mapping", mapping)

		if aslrElegible {
			adjustedLoadAddress = mapping.LoadAddr
		}
	} else {
		adjustedLoadAddress = mapping.LoadAddr
	}

	level.Debug(m.logger).Log("msg", "adding memory mappings in for executable", "executableID", m.executableID, "buildID", buildID, "executable", mapping.Executable)

	// Add the memory mapping information.
	foundexecutableID, mappingAlreadySeen := m.mappingID(buildID)

	err = m.writeMapping(procInfoBuf, adjustedLoadAddress, mapping.StartAddr, mapping.EndAddr, foundexecutableID, uint64(0))
	if err != nil {
		return fmt.Errorf("writing mappings failed with %w", err)
	}

	// Generated and add the unwind table, if needed.
	if !mappingAlreadySeen {
		unwindShardsKeyBuf := new(bytes.Buffer)
		unwindShardsValBuf := new(bytes.Buffer)

		// ==================================== generate unwind table

		// PERF(javierhonduco): Not reusing a buffer here yet, let's profile and decide whether this
		// change would be worth it.
		ut, minCoveredPc, maxCoveredPc, err := m.generateCompactUnwindTable(fullExecutablePath, mapping)
		if err != nil {
			if errors.Is(err, unwind.ErrNoFDEsFound) {
				// is it ok to return here?
				return nil
			}
			if errors.Is(err, unwind.ErrEhFrameSectionNotFound) {
				// is it ok to return here?
				return nil
			}
			return nil
		}

		if len(ut) == 0 {
			return nil
		}

		threshold := min(uint64(len(ut)), m.availableEntries())
		currentChunk := ut[:threshold]
		restChunks := ut[threshold:]

		numShards := len(ut) / maxUnwindTableSize
		// The above numShards is correct if the unwind table we want to add
		// snugly fits in the available space. We occupy one more shard if we
		// don't have an empty live shard and if don't perfectly fit in the
		// available space.
		if m.highIndex%maxUnwindTableSize == 0 && uint64(len(ut)) > m.availableEntries() {
			numShards++
		}

		// .len
		if err := binary.Write(unwindShardsValBuf, m.byteOrder, uint64(numShards)); err != nil {
			return fmt.Errorf("write shards .len bytes: %w", err)
		}

		chunkIndex := 0

		for {
			m.assertInvariants()

			level.Debug(m.logger).Log("current chunk size", len(currentChunk))
			level.Debug(m.logger).Log("rest of chunk size", len(restChunks))

			m.totalEntries += uint64(len(currentChunk))

			if len(currentChunk) == 0 {
				level.Debug(m.logger).Log("msg", "done with the last chunk")
				break
			}

			m.highIndex += uint64(len(currentChunk))
			level.Debug(m.logger).Log("lowindex", m.lowIndex)
			level.Debug(m.logger).Log("highIndex", m.highIndex)

			// ======================== shard info ===============================

			level.Debug(m.logger).Log("executableID", m.executableID, "executable", mapping.Executable, "current shard", chunkIndex)

			if err := binary.Write(unwindShardsKeyBuf, m.byteOrder, m.executableID); err != nil {
				return fmt.Errorf("write shards key bytes: %w", err)
			}

			// Dealing with the first chunk, we must add the lowest known PC.
			minPc := currentChunk[0].Pc()
			if chunkIndex == 0 {
				minPc = minCoveredPc
			}
			// .low_pc
			if err := binary.Write(unwindShardsValBuf, m.byteOrder, minPc); err != nil {
				return fmt.Errorf("write shards .low_pc bytes: %w", err)
			}

			// Dealing with the last chunk, we must add the highest known PC.
			maxPc := currentChunk[len(currentChunk)-1].Pc()
			if chunkIndex == numShards {
				maxPc = maxCoveredPc
			}
			// .high_pc
			if err := binary.Write(unwindShardsValBuf, m.byteOrder, maxPc); err != nil {
				return fmt.Errorf("write shards .high_pc bytes: %w", err)
			}

			// .shard_index
			if err := binary.Write(unwindShardsValBuf, m.byteOrder, m.shardIndex); err != nil {
				return fmt.Errorf("write shards .shard_index bytes: %w", err)
			}

			// .low_index
			if err := binary.Write(unwindShardsValBuf, m.byteOrder, m.lowIndex); err != nil {
				return fmt.Errorf("write shards .low_index bytes: %w", err)
			}
			// .high_index
			if err := binary.Write(unwindShardsValBuf, m.byteOrder, m.highIndex); err != nil {
				return fmt.Errorf("write shards .high_index bytes: %w", err)
			}

			m.lowIndex = m.highIndex

			// ====================== Write unwind table =====================
			for _, row := range currentChunk {
				if err := m.writeUnwindTableRow(m.unwindInfoBuf, row); err != nil {
					return fmt.Errorf("writing unwind table row: %w", err)
				}
			}

			// Need a new shard?
			if m.availableEntries() == 0 {
				level.Info(m.logger).Log("msg", "run out of space in the 'live' shard, creating a new one")

				err := m.PersistUnwindTable()
				if err != nil {
					return fmt.Errorf("failed to write unwind table: %w", err)
				}

				m.shardIndex++
				if err := m.resetInFlightBuffer(); err != nil {
					level.Error(m.logger).Log("msg", "resetInFlightBuffer failed", "err", err)
				}
				m.lowIndex = 0
				m.highIndex = 0

				if m.shardIndex == unwindTableMaxEntries {
					level.Error(m.logger).Log("msg", "Not enough shards - this is not implemented but we should deal with this")
				}
			}

			// Recalculate for next iteration
			threshold := min(uint64(len(restChunks)), m.availableEntries())
			currentChunk = restChunks[:threshold]
			restChunks = restChunks[threshold:]

			chunkIndex++
		}

		if err := m.unwindShards.Update(
			unsafe.Pointer(&unwindShardsKeyBuf.Bytes()[0]),
			unsafe.Pointer(&unwindShardsValBuf.Bytes()[0])); err != nil {
			return fmt.Errorf("failed to update unwind shard: %w", err)
		}

		m.executableID++
		m.uniqueMappings++
	}

	return nil
}
