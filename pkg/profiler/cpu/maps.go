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
	"sync"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"golang.org/x/exp/constraints"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/elfreader"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

const (
	debugPIDsMapName   = "debug_pids"
	stackCountsMapName = "stack_counts"
	stackTracesMapName = "stack_traces"

	unwindInfoChunksMapName = "unwind_info_chunks"
	dwarfStackTracesMapName = "dwarf_stack_traces"
	unwindTablesMapName     = "unwind_tables"
	processInfoMapName      = "process_info"
	programsMapName         = "programs"
	perCPUStatsMapName      = "percpu_stats"

	// With the current compact rows, the max items we can store in the kernels
	// we have tested is 262k per map, which we rounded it down to 250k.
	maxUnwindShards       = 50         // How many unwind table shards we have.
	maxUnwindTableSize    = 250 * 1000 // Always needs to be sync with MAX_UNWIND_TABLE_SIZE in the BPF program.
	maxMappingsPerProcess = 250        // Always need to be in sync with MAX_MAPPINGS_PER_PROCESS.
	maxUnwindTableChunks  = 30         // Always need to be in sync with MAX_UNWIND_TABLE_CHUNKS.
	maxProcesses          = 5000       // Always need to be in sync with MAX_PROCESSES.

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
	mappingInfoSizeBytes = 8 + 8 + (maxMappingsPerProcess * 8 * 5)
	/*
		TODO: once we generate the bindings automatically, remove this.

		typedef struct shard_info {
			u64 low_pc;
			u64 high_pc;
			u64 shard_index;
			u64 low_index;
			u64 high_index;
		} shard_info_t;

		typedef struct stack_unwind_table_shards {
			shard_info_t shards[MAX_UNWIND_TABLE_CHUNKS];
		} stack_unwind_table_shards_t;
	*/
	unwindShardsSizeBytes = maxUnwindTableChunks * 8 * 5
	/*
		typedef struct __attribute__((packed)) {
			u64 pc;
			u8 cfa_type;
			u8 rbp_type;
			s16 cfa_offset;
			s16 rbp_offset;
		} stack_unwind_row_t;
	*/
	compactUnwindRowSizeBytes                = 14
	minRoundsBeforeRedoingUnwindInfo         = 5
	minRoundsBeforeRedoingProcessInformation = 5
	maxCachedProcesses                       = 10_0000
)

// Must be in sync with the BPF program.
type unwinderStats struct {
	Total                       uint64
	SuccessDwarf                uint64
	ErrorTruncated              uint64
	ErrorUnsupportedExpression  uint64
	ErrorFramePointerAction     uint64
	ErrorUnsupportedCfaRegister uint64
	ErrorCatchall               uint64
	ErrorShouldNeverHappen      uint64
	ErrorPcNotCovered           uint64
	ErrorJitUnupdatedMapping    uint64
	ErrorJitMixedModeDisabled   uint64
	ErrorPcNotCoveredJit        uint64
	ErrorJitUnwindingMachinery  uint64
	SuccessJitFrame             uint64
	SuccessJitToDwarf           uint64
	SuccessDwarfToJit           uint64
	SuccessDwarfReachBottom     uint64
	SuccessJitReachBottom       uint64
}

const (
	mappingTypeJitted  = 1
	mappingTypeSpecial = 2
)

const (
	RequestUnwindInformation = 1 << 63
	RequestProcessMappings   = 1 << 62
	RequestRefreshProcInfo   = 1 << 61
)

var (
	errMissing                   = errors.New("missing stack trace")
	errUnwindFailed              = errors.New("stack ID is 0, probably stack unwinding failed")
	errUnrecoverable             = errors.New("unrecoverable error")
	errTooManyExecutableMappings = errors.New("too many executable mappings")
	ErrNeedMoreProfilingRounds   = errors.New("not enough profiling rounds with this unwind info")
)

func clearBpfMap(bpfMap *bpf.BPFMap) error {
	// BPF iterators need the previous value to iterate to the next, so we
	// can only delete the "previous" item once we've already iterated to
	// the next.

	it := bpfMap.Iterator()
	var prev []byte = nil
	for it.Next() {
		if prev != nil {
			err := bpfMap.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("failed to delete map key: %w", err)
			}
		}

		key := it.Key()
		prev = make([]byte, len(key))
		copy(prev, key)
	}
	if prev != nil {
		err := bpfMap.DeleteKey(unsafe.Pointer(&prev[0]))
		if err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("failed to delete map key: %w", err)
		}
	}

	return nil
}

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

	// Unwind stuff 🔬
	processCache      *processCache
	mappingInfoMemory profiler.EfficientBuffer

	buildIDMapping map[string]uint64
	// Which shard we are using
	maxUnwindShards  uint64
	shardIndex       uint64
	executableID     uint64
	unwindInfoMemory profiler.EfficientBuffer
	// Account where we are within a shard
	lowIndex  uint64
	highIndex uint64
	// Other stats
	totalEntries       uint64
	uniqueMappings     uint64
	referencedMappings uint64
	// Counters to ensure we don't clear the unwind info too
	// quickly if we run out of shards.
	waitingToResetUnwindInfo              bool
	profilingRoundsWithoutUnwindInfoReset int64
	// Counters to ensure we don't clear the process info too
	// quickly if we run out of space.
	waitingToResetProcessInfo              bool
	profilingRoundsWithoutProcessInfoReset int64

	mutex sync.Mutex
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

type processCache struct {
	*cache.LRUCache[int, uint64]
}

func newProcessCache(logger log.Logger, reg prometheus.Registerer) *processCache {
	return &processCache{
		cache.NewLRUCache[int, uint64](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "cpu_map"}, reg),
			maxCachedProcesses,
		),
	}
}

// close closes the cache and makes sure the stats counter is unregistered.
func (c *processCache) close() error {
	// Close the cache and that unregisters the stats counter before closing the cache,
	// in case the cache could be initialized again.
	if err := c.Close(); err != nil {
		return errors.Join(err, fmt.Errorf("failed to close process cache: %w", err))
	}
	return nil
}

func initializeMaps(logger log.Logger, reg prometheus.Registerer, m *bpf.Module, byteOrder binary.ByteOrder) (*bpfMaps, error) {
	if m == nil {
		return nil, fmt.Errorf("nil module")
	}

	mappingInfoMemory := make([]byte, 0, mappingInfoSizeBytes)
	unwindInfoMemory := make([]byte, maxUnwindTableSize*compactUnwindRowSizeBytes)

	maps := &bpfMaps{
		logger:            log.With(logger, "component", "bpf_maps"),
		module:            m,
		byteOrder:         byteOrder,
		processCache:      newProcessCache(logger, reg),
		mappingInfoMemory: mappingInfoMemory,
		unwindInfoMemory:  unwindInfoMemory,
		buildIDMapping:    make(map[string]uint64),
		mutex:             sync.Mutex{},
	}

	if err := maps.resetInFlightBuffer(); err != nil {
		level.Error(logger).Log("msg", "resetInFlightBuffer failed", "err", err)
	}

	return maps, nil
}

// close closes all the resources associated with the maps.
func (m *bpfMaps) close() error {
	return m.processCache.close()
}

// adjustMapSizes updates the amount of unwind shards.
//
// Note: It must be called before `BPFLoadObject()`.
func (m *bpfMaps) adjustMapSizes(debugEnabled bool, unwindTableShards uint32) error {
	unwindTables, err := m.module.GetMap(unwindTablesMapName)
	if err != nil {
		return fmt.Errorf("get unwind tables map: %w", err)
	}

	// Adjust unwind_tables size.
	sizeBefore := unwindTables.GetMaxEntries()
	if err := unwindTables.Resize(unwindTableShards); err != nil {
		return fmt.Errorf("resize unwind tables map from %d to %d elements: %w", sizeBefore, unwindTableShards, err)
	}

	m.maxUnwindShards = uint64(unwindTableShards)

	// Adjust debug_pids size.
	if debugEnabled {
		debugPIDs, err := m.module.GetMap(debugPIDsMapName)
		if err != nil {
			return fmt.Errorf("get debug pids map: %w", err)
		}
		if err := debugPIDs.Resize(maxProcesses); err != nil {
			return fmt.Errorf("resize debug pids map from default to %d elements: %w", maxProcesses, err)
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

	unwindShards, err := m.module.GetMap(unwindInfoChunksMapName)
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
		return fmt.Errorf("read user stack trace, %w: %w", err, errMissing)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, stack[:stackDepth]); err != nil {
		return fmt.Errorf("read user stack bytes, %w: %w", err, errUnrecoverable)
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
		return fmt.Errorf("read user stack trace, %w: %w", err, errMissing)
	}

	var dwarfStack dwarfStacktrace
	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, &dwarfStack); err != nil {
		return fmt.Errorf("read user stack bytes, %w: %w", err, errUnrecoverable)
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
		return fmt.Errorf("read kernel stack trace, %w: %w", err, errMissing)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, stack[stackDepth:]); err != nil {
		return fmt.Errorf("read kernel stack bytes, %w: %w", err, errUnrecoverable)
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

func (m *bpfMaps) cleanStacks() error {
	var result error

	// stackTraces
	if err := clearBpfMap(m.stackTraces); err != nil {
		result = errors.Join(result, err)
	}

	// dwarfStackTraces
	if err := clearBpfMap(m.dwarfStackTraces); err != nil {
		result = errors.Join(result, err)
	}

	// stackCounts
	if err := clearBpfMap(m.stackCounts); err != nil {
		result = errors.Join(result, err)
	}

	return result
}

func (m *bpfMaps) finalizeProfileLoop() error {
	m.profilingRoundsWithoutUnwindInfoReset++
	m.profilingRoundsWithoutProcessInfoReset++
	return m.cleanStacks()
}

func (m *bpfMaps) cleanProcessInfo() error {
	if err := clearBpfMap(m.processInfo); err != nil {
		return err
	}
	return nil
}

func (m *bpfMaps) cleanShardInfo() error {
	// unwindShards
	if err := clearBpfMap(m.unwindShards); err != nil {
		return err
	}
	return nil
}

func (m *bpfMaps) resetMappingInfoBuffer() error {
	// Extend length to match the capacity.
	m.mappingInfoMemory = m.mappingInfoMemory[:cap(m.mappingInfoMemory)]

	// Zero it.
	for i := 0; i < cap(m.mappingInfoMemory); i++ {
		m.mappingInfoMemory[i] = 0
	}

	// Reset length.
	m.mappingInfoMemory = m.mappingInfoMemory[:0]
	return nil
}

// refreshProcessInfo updates the process information such as mappings and unwind
// information if the executable mappings have changed.
func (m *bpfMaps) refreshProcessInfo(pid int) {
	level.Debug(m.logger).Log("msg", "refreshing process info", "pid", pid)

	cachedHash, _ := m.processCache.Get(pid)

	proc, err := procfs.NewProc(pid)
	if err != nil {
		return
	}
	mappings, err := proc.ProcMaps()
	if err != nil {
		return
	}
	executableMappings := unwind.ListExecutableMappings(mappings)
	currentHash, err := executableMappings.Hash()
	if err != nil {
		level.Error(m.logger).Log("msg", "executableMappings hash failed", "err", err)
		return
	}

	if cachedHash != currentHash {
		err := m.addUnwindTableForProcess(pid, executableMappings, false)
		if err != nil {
			level.Error(m.logger).Log("msg", "addUnwindTableForProcess failed", "err", err)
		}
	}
}

// 1. Find executable sections
// 2. For each section, generate compact table
// 3. Add table to maps
// 4. Add map metadata to process
func (m *bpfMaps) addUnwindTableForProcess(pid int, executableMappings unwind.ExecutableMappings, checkCache bool) error {
	// Notes:
	//	- perhaps we could cache based on `start_at` (but parsing this procfs file properly
	// is challenging if the process name contains spaces, etc).
	//  - PIDs can be recycled.

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if checkCache {
		if _, exists := m.processCache.Get(pid); exists {
			level.Debug(m.logger).Log("msg", "process already cached", "pid", pid)
			return nil
		}
	}

	if executableMappings == nil {
		proc, err := procfs.NewProc(pid)
		if err != nil {
			return err
		}
		mappings, err := proc.ProcMaps()
		if err != nil {
			return err
		}
		executableMappings = unwind.ListExecutableMappings(mappings)
	}

	// Clean up the mapping information.
	if err := m.resetMappingInfoBuffer(); err != nil {
		level.Error(m.logger).Log("msg", "resetMappingInfoBuffer failed", "err", err)
	}

	// Important: the below *must* be called before setUnwindTable.
	// .is_jit_compiler
	var isJitCompiler uint64
	if executableMappings.HasJitted() {
		isJitCompiler = 1
	}

	if len(executableMappings) >= maxMappingsPerProcess {
		return errTooManyExecutableMappings
	}

	mappingInfoMemory := m.mappingInfoMemory.Slice(mappingInfoSizeBytes)
	// .type
	mappingInfoMemory.PutUint64(isJitCompiler)
	// .len
	mappingInfoMemory.PutUint64(uint64(len(executableMappings)))

	for _, executableMapping := range executableMappings {
		if executableMapping.IsJitDump() {
			continue
		}
		if err := m.setUnwindTableForMapping(&mappingInfoMemory, pid, executableMapping); err != nil {
			return fmt.Errorf("setUnwindTableForMapping for executable %s starting at 0x%x failed: %w", executableMapping.Executable, executableMapping.StartAddr, err)
		}
	}

	// TODO(javierhonduco): There's a small window where it's possible that
	// the unwind information hasn't been written to the map while the process
	// information has. During this window unwinding might fail. Particularly,
	// this is a problem when we decide to delay regenerating the dwarf state
	// when running out of shards.
	if err := m.processInfo.Update(unsafe.Pointer(&pid), unsafe.Pointer(&m.mappingInfoMemory[0])); err != nil {
		if errors.Is(err, syscall.E2BIG) {
			if m.profilingRoundsWithoutProcessInfoReset < minRoundsBeforeRedoingProcessInformation {
				level.Debug(m.logger).Log("msg", "not enough profile loops, we need to wait to reset proc info")
				m.waitingToResetProcessInfo = true
				return nil
			}

			if m.waitingToResetProcessInfo {
				level.Debug(m.logger).Log("msg", "no need to wait anymore to reset proc info")
				m.waitingToResetProcessInfo = false
				m.profilingRoundsWithoutProcessInfoReset = 0
			}

			m.processCache.Purge()
			cleanErr := m.cleanProcessInfo()
			level.Info(m.logger).Log("msg", "resetting process information", "cleanErr", cleanErr)

			// Next call will populate the process info.
			return nil
		}
		return fmt.Errorf("update processInfo: %w", err)
	}

	mapsHash, err := executableMappings.Hash()
	if err != nil {
		return fmt.Errorf("maps hash: %w", err)
	}
	m.processCache.Add(pid, mapsHash)
	return nil
}

// generateCompactUnwindTable produces the compact unwidn table for a given
// executable.
func (m *bpfMaps) generateCompactUnwindTable(fullExecutablePath string, mapping *unwind.ExecutableMapping) (unwind.CompactUnwindTable, error) {
	var ut unwind.CompactUnwindTable

	// Fetch FDEs.
	fdes, err := unwind.ReadFDEs(fullExecutablePath)
	if err != nil {
		return ut, err
	}

	// Sort them, as this will ensure that the generated table
	// is also sorted. Sorting fewer elements will be faster.
	sort.Sort(fdes)

	// Generate the compact unwind table.
	ut, err = unwind.BuildCompactUnwindTable(fdes)
	if err != nil {
		return ut, err
	}

	// This should not be necessary, as per the sorting above, but
	// just in case :).
	sort.Sort(ut)

	// Now we have a full compact unwind table that we have to split in different BPF maps.
	level.Debug(m.logger).Log("msg", "found unwind entries", "executable", mapping.Executable, "len", len(ut))

	return ut, nil
}

// writeUnwindTableRow writes a compact unwind table row to the provided slice.
//
// Note: we are avoiding `binary.Write` and prefer to use the lower level APIs
// to avoid allocations and CPU spent in the reflection code paths as well as
// in the allocations for the intermediate buffers.
func (m *bpfMaps) writeUnwindTableRow(rowSlice *profiler.EfficientBuffer, row unwind.CompactUnwindTableRow) {
	// .pc
	rowSlice.PutUint64(row.Pc())
	// .cfa_type
	rowSlice.PutUint8(row.CfaType())
	// .rbp_type
	rowSlice.PutUint8(row.RbpType())
	// .cfa_offset
	rowSlice.PutInt16(row.CfaOffset())
	// .rbp_offset
	rowSlice.PutInt16(row.RbpOffset())
}

// writeMapping writes the memory mapping information to the provided buffer.
//
// Note: we write field by field to avoid the expensive reflection code paths
// when writing structs using `binary.Write`.
func (m *bpfMaps) writeMapping(buf *profiler.EfficientBuffer, loadAddress, startAddr, endAddr, executableID, type_ uint64) {
	// .load_address
	buf.PutUint64(loadAddress)
	// .begin
	buf.PutUint64(startAddr)
	// .end
	buf.PutUint64(endAddr)
	// .executable_id
	buf.PutUint64(executableID)
	// .type
	buf.PutUint64(type_)
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
	// Extend length to match the capacity.
	m.unwindInfoMemory = m.unwindInfoMemory[:cap(m.unwindInfoMemory)]

	// Zero it.
	for i := 0; i < cap(m.unwindInfoMemory); i++ {
		m.unwindInfoMemory[i] = 0
	}

	// Reset slice's len.
	m.unwindInfoMemory = m.unwindInfoMemory[:0]
	return nil
}

// PersistUnwindTable calls persistUnwindTable but holding the mutex
// to ensure that shared state is mutated safely.
//
// Never use this function from addUnwindTableForProcess, as it holds
// this same mutex.
func (m *bpfMaps) PersistUnwindTable() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.persistUnwindTable()
}

// persistUnwindTable writes the current in-flight, writable shard
// to the corresponding BPF map's shard.
//
// Note: as of now, this must be called in two situations:
//   - In the callsite, once we are done with generating the unwind
//     tables (see PersistUnwindTable).
//   - Whenever the current in-flight shard is full, before we wipe
//     it and start reusing it.
func (m *bpfMaps) persistUnwindTable() error {
	totalRows := len(m.unwindInfoMemory) / compactUnwindRowSizeBytes
	if totalRows > maxUnwindTableSize {
		panic("totalRows > maxUnwindTableSize should never happen")
	}
	level.Debug(m.logger).Log("msg", "PersistUnwindTable called", "live unwind rows", totalRows)

	if totalRows == 0 {
		return nil
	}

	shardIndex := m.shardIndex

	err := m.unwindTables.Update(unsafe.Pointer(&shardIndex), unsafe.Pointer(&m.unwindInfoMemory[0]))
	if err != nil {
		if errors.Is(err, syscall.E2BIG) {
			// If we need to wipe all state because we run out of shards, let's only do it after few
			// profiling rounds.
			//
			// It's the responsibility of the caller to ensure that the processes to be profiled have
			// a fair ordering.
			if m.profilingRoundsWithoutUnwindInfoReset < minRoundsBeforeRedoingUnwindInfo {
				level.Debug(m.logger).Log("msg", "not enough profile loops, we need to wait to reset unwind info")
				m.waitingToResetUnwindInfo = true
				return ErrNeedMoreProfilingRounds
			}

			if m.waitingToResetUnwindInfo {
				level.Debug(m.logger).Log("msg", "no need to wait anymore to reset unwind info")
				m.waitingToResetUnwindInfo = false
				m.profilingRoundsWithoutUnwindInfoReset = 0
			}

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
	m.processCache.Purge()
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

	if err := m.cleanProcessInfo(); err != nil {
		level.Error(m.logger).Log("msg", "cleanProcessInfo failed", "err", err)
		return err
	}
	if err := m.cleanShardInfo(); err != nil {
		level.Error(m.logger).Log("msg", "cleanShardInfo failed", "err", err)
		return err
	}
	if err := m.cleanStacks(); err != nil {
		level.Error(m.logger).Log("msg", "cleanStacks failed", "err", err)
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
		panic(fmt.Sprintf("m.highIndex (%d)> 250k, this should never happen", m.highIndex))
	}
	tableSize := len(m.unwindInfoMemory) / compactUnwindRowSizeBytes
	if tableSize > maxUnwindTableSize {
		panic(fmt.Sprintf("unwindInfoBuf has %d entries, more than the 250k max", tableSize))
	}
	if m.availableEntries() == 0 {
		panic("no space left in the in-flight shard, this should never happen")
	}
}

// allocateNewShard uses a new shard. This must be called whenever we ran out of space
// in the current "live" shard, or when we want to avoid splitting a function's unwind
// information.
func (m *bpfMaps) allocateNewShard() error {
	err := m.persistUnwindTable()
	if err != nil {
		return fmt.Errorf("failed to write unwind table: %w", err)
	}

	if err := m.resetInFlightBuffer(); err != nil {
		level.Error(m.logger).Log("msg", "resetInFlightBuffer failed", "err", err)
	}

	m.shardIndex++
	m.lowIndex = 0
	m.highIndex = 0

	if m.shardIndex == m.maxUnwindShards {
		level.Debug(m.logger).Log("msg", "next shard persist will reset the unwind info")
	}

	return nil
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
//
// - This function is *not* safe to be called concurrently, the caller, addUnwindTableForProcess
// uses a mutex to ensure safe data access.
func (m *bpfMaps) setUnwindTableForMapping(buf *profiler.EfficientBuffer, pid int, mapping *unwind.ExecutableMapping) error {
	level.Debug(m.logger).Log("msg", "setUnwindTable called", "shards", m.shardIndex, "max shards", m.maxUnwindShards, "sum of unwind rows", m.totalEntries)

	// Deal with mappings that are not filed backed. They don't have unwind
	// information.
	if mapping.IsNotFileBacked() {
		var type_ uint64
		if mapping.IsJitted() {
			level.Debug(m.logger).Log("msg", "jit section", "pid", pid)
			type_ = mappingTypeJitted
		}
		if mapping.IsSpecial() {
			level.Debug(m.logger).Log("msg", "special section", "pid", pid)
			type_ = mappingTypeSpecial
		}

		m.writeMapping(buf, mapping.LoadAddr, mapping.StartAddr, mapping.EndAddr, uint64(0), type_)
		return nil
	}

	// TODO(kakkoyun): Migrate objectfile and pool.

	// Deal with mappings that are backed by a file and might contain unwind
	// information.
	fullExecutablePath := path.Join("/proc/", fmt.Sprintf("%d", pid), "/root/", mapping.Executable)

	f, err := os.Open(fullExecutablePath)
	if err != nil {
		return err
	}

	ef, err := elf.NewFile(f)
	var elfErr *elf.FormatError
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if errors.As(err, &elfErr) {
			level.Debug(m.logger).Log("msg", "bad ELF file format", "err", err)
			return nil
		}
		return fmt.Errorf("elf.Open failed: %w", err)
	}
	buildID, err := buildid.FromELF(ef)
	if err != nil {
		return fmt.Errorf("BuildID failed %s: %w", fullExecutablePath, err)
	}

	// Find the adjusted load address.
	aslrElegible := elfreader.IsASLRElegibleElf(ef)

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

	m.writeMapping(buf, adjustedLoadAddress, mapping.StartAddr, mapping.EndAddr, foundexecutableID, uint64(0))

	// Generated and add the unwind table, if needed.
	if !mappingAlreadySeen {
		unwindShardsValBuf := new(bytes.Buffer)
		unwindShardsValBuf.Grow(unwindShardsSizeBytes)

		// Generate the unwind table.
		// PERF(javierhonduco): Not reusing a buffer here yet, let's profile and decide whether this
		// change would be worth it.
		ut, err := m.generateCompactUnwindTable(fullExecutablePath, mapping)
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

		chunkIndex := 0

		var (
			currentChunk unwind.CompactUnwindTable
			restChunks   unwind.CompactUnwindTable
		)

		restChunks = ut

		for {
			if m.waitingToResetUnwindInfo {
				return ErrNeedMoreProfilingRounds
			}
			maxThreshold := min(len(restChunks), int(m.availableEntries()))

			if maxThreshold == 0 {
				level.Debug(m.logger).Log("msg", "done with the last chunk")
				break
			}

			// Find the end of the last function and split the unwind table
			// at that index.
			currentChunkCandidate := restChunks[:maxThreshold]
			threshold := maxThreshold
			for i := maxThreshold - 1; i >= 0; i-- {
				if currentChunkCandidate[i].IsEndOfFDEMarker() {
					break
				}
				threshold--
			}

			// We couldn't find a full function in the current unwind information.
			// As we can't split an unwind table mid-function, let's create a new
			// shard.
			if threshold == 0 {
				level.Debug(m.logger).Log("msg", "creating a new shard to avoid splitting the unwind table for a function")
				if err := m.allocateNewShard(); err != nil {
					return err
				}
				continue
			}

			currentChunk = restChunks[:threshold]
			restChunks = restChunks[threshold:]

			if currentChunk[0].IsEndOfFDEMarker() {
				level.Error(m.logger).Log("msg", "First row of a chunk should not be a marker")
			}

			if !currentChunk[len(currentChunk)-1].IsEndOfFDEMarker() {
				level.Error(m.logger).Log("msg", "Last row of a chunk should always be a marker")
			}

			m.assertInvariants()

			if chunkIndex >= maxUnwindTableChunks {
				level.Error(m.logger).Log("msg", "have more chunks than the max", "chunks", chunkIndex, "maxChunks", maxUnwindTableChunks)
				// TODO(javierhonduco): not returning an error right now, but let's handle this later on.
			}

			level.Debug(m.logger).Log("current chunk size", len(currentChunk))
			level.Debug(m.logger).Log("rest of chunk size", len(restChunks))

			m.totalEntries += uint64(len(currentChunk))

			m.highIndex += uint64(len(currentChunk))
			level.Debug(m.logger).Log("lowindex", m.lowIndex)
			level.Debug(m.logger).Log("highIndex", m.highIndex)

			// Add shard information.

			level.Debug(m.logger).Log("executableID", m.executableID, "executable", mapping.Executable, "current shard", chunkIndex)

			// Dealing with the first chunk, we must add the lowest known PC.
			minPc := currentChunk[0].Pc()
			if minPc == 0 {
				panic("maxPC can't be zero")
			}
			// .low_pc
			if err := binary.Write(unwindShardsValBuf, m.byteOrder, minPc); err != nil {
				return fmt.Errorf("write shards .low_pc bytes: %w", err)
			}

			// Dealing with the last chunk, we must add the highest known PC.
			maxPc := currentChunk[len(currentChunk)-1].Pc()
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

			// Write unwind table.
			for _, row := range currentChunk {
				// Get a slice of the bytes we need for this row.
				rowSlice := m.unwindInfoMemory.Slice(compactUnwindRowSizeBytes)
				m.writeUnwindTableRow(&rowSlice, row)
			}

			// We ran out of space in the current shard. Let's allocate a new one.
			if m.availableEntries() == 0 {
				level.Info(m.logger).Log("msg", "creating a new shard as we ran out of space")

				if err := m.allocateNewShard(); err != nil {
					return err
				}
			}

			chunkIndex++
		}

		executableID := m.executableID
		if err := m.unwindShards.Update(
			unsafe.Pointer(&executableID),
			unsafe.Pointer(&unwindShardsValBuf.Bytes()[0])); err != nil {
			return fmt.Errorf("failed to update unwind shard: %w", err)
		}

		m.executableID++
		m.uniqueMappings++
	}

	return nil
}
