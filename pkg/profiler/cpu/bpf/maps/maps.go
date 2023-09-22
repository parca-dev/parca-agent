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

package bpfmaps

import "C"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Masterminds/semver/v3"
	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"golang.org/x/exp/constraints"

	"github.com/parca-dev/runtime-data/pkg/python"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/elfreader"
	"github.com/parca-dev/parca-agent/pkg/profile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu/bpf"
	bpfprograms "github.com/parca-dev/parca-agent/pkg/profiler/cpu/bpf/programs"
	"github.com/parca-dev/parca-agent/pkg/profiler/pyperf"
	"github.com/parca-dev/parca-agent/pkg/profiler/rbperf"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

const (
	DebugPIDsMapName              = "debug_pids"
	StackCountsMapName            = "stack_counts"
	eventsCountMapName            = "events_count"
	StackTracesMapName            = "stack_traces"
	HeapMapName                   = "heap"
	InterpreterStackTracesMapName = "interpreter_stack_traces"
	SymbolIndexStorageMapName     = "symbol_index_storage"
	SymbolTableMapName            = "symbol_table"
	eventsMapName                 = "events"

	// rbperf maps.
	RubyPIDToRubyThreadMapName       = "pid_to_rb_thread"
	RubyVersionSpecificOffsetMapName = "version_specific_offsets"

	// pyperf maps.
	PythonPIDToInterpreterInfoMapName  = "pid_to_interpreter_info"
	PythonVersionSpecificOffsetMapName = "version_specific_offsets"

	UnwindInfoChunksMapName = "unwind_info_chunks"
	DWARFStackTracesMapName = "dwarf_stack_traces"
	UnwindTablesMapName     = "unwind_tables"
	ProcessInfoMapName      = "process_info"
	ProgramsMapName         = "programs"
	PerCPUStatsMapName      = "percpu_stats"

	// With the current compact rows, the max items we can store in the kernels
	// we have tested is 262k per map, which we rounded it down to 250k.
	MaxUnwindShards       = 50         // How many unwind table shards we have.
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
			s16 lr_offset;(if arch == EM_AARCH64)
			u8 cfa_type;
			u8 rbp_type;
			s16 cfa_offset;
			s16 rbp_offset;
		} stack_unwind_row_t;
	*/
	compactUnwindRowSizeBytesX86             = 14
	compactUnwindRowSizeBytesArm64           = 16
	minRoundsBeforeRedoingUnwindInfo         = 5
	minRoundsBeforeRedoingProcessInformation = 5
	maxCachedProcesses                       = 10_0000

	defaultSymbolTableSize = 64000
)

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
	ErrMissing                   = errors.New("missing stack trace")
	ErrUnwindFailed              = errors.New("stack ID is 0, probably stack unwinding failed")
	ErrUnrecoverable             = errors.New("unrecoverable error")
	ErrTooManyExecutableMappings = errors.New("too many executable mappings")
	ErrNeedMoreProfilingRounds   = errors.New("not enough profiling rounds with this unwind info")
)

type Maps struct {
	logger  log.Logger
	metrics *metrics

	byteOrder binary.ByteOrder

	nativeModule *libbpf.Module
	rbperfModule *libbpf.Module
	pyperfModule *libbpf.Module

	debugPIDs *libbpf.BPFMap

	StackCounts                *libbpf.BPFMap
	eventsCount                *libbpf.BPFMap
	stackTraces                *libbpf.BPFMap
	dwarfStackTraces           *libbpf.BPFMap
	interpreterStackTraces     *libbpf.BPFMap
	symbolTable                *libbpf.BPFMap
	rubyPIDToThread            *libbpf.BPFMap
	rubyVersionSpecificOffsets *libbpf.BPFMap

	pythonPIDToProcessInfo       *libbpf.BPFMap
	pythonVersionSpecificOffsets *libbpf.BPFMap
	pythonVersionToOffsetIndex   map[string]uint32

	unwindShards *libbpf.BPFMap
	unwindTables *libbpf.BPFMap
	programs     *libbpf.BPFMap
	processInfo  *libbpf.BPFMap

	// Unwind stuff 🔬
	processCache      *processCache
	mappingInfoMemory profiler.EfficientBuffer

	buildIDMapping map[string]uint64
	// Which shard we are using
	maxUnwindShards           uint64
	shardIndex                uint64
	executableID              uint64
	compactUnwindRowSizeBytes int
	unwindInfoMemory          profiler.EfficientBuffer
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

type ProfilerModuleType int

const (
	NativeModule ProfilerModuleType = iota
	RbperfModule
	PyperfModule
)

func New(logger log.Logger, reg prometheus.Registerer, byteOrder binary.ByteOrder, arch elf.Machine, modules map[ProfilerModuleType]*libbpf.Module) (*Maps, error) {
	if modules[NativeModule] == nil {
		return nil, fmt.Errorf("nil nativeModule")
	}

	var compactUnwindRowSizeBytes int
	switch arch {
	case elf.EM_AARCH64:
		compactUnwindRowSizeBytes = compactUnwindRowSizeBytesArm64
	case elf.EM_X86_64:
		compactUnwindRowSizeBytes = compactUnwindRowSizeBytesX86
	default:
		level.Error(logger).Log("msg", "unknown architecture", "arch", arch)
	}

	mappingInfoMemory := make([]byte, 0, mappingInfoSizeBytes)
	unwindInfoMemory := make([]byte, maxUnwindTableSize*compactUnwindRowSizeBytes)

	maps := &Maps{
		logger:                     log.With(logger, "component", "bpf_maps"),
		metrics:                    newMetrics(reg),
		nativeModule:               modules[NativeModule],
		rbperfModule:               modules[RbperfModule],
		pyperfModule:               modules[PyperfModule],
		byteOrder:                  byteOrder,
		processCache:               newProcessCache(logger, reg),
		mappingInfoMemory:          mappingInfoMemory,
		compactUnwindRowSizeBytes:  compactUnwindRowSizeBytes,
		unwindInfoMemory:           unwindInfoMemory,
		buildIDMapping:             make(map[string]uint64),
		mutex:                      sync.Mutex{},
		pythonVersionToOffsetIndex: make(map[string]uint32),
	}

	if err := maps.resetInFlightBuffer(); err != nil {
		level.Error(logger).Log("msg", "resetInFlightBuffer failed", "err", err)
	}

	return maps, nil
}

func (m *Maps) ReuseMaps() error {
	if m.pyperfModule == nil && m.rbperfModule == nil {
		return nil
	}

	// Fetch native maps.
	heapNative, err := m.nativeModule.GetMap(HeapMapName)
	if err != nil {
		return fmt.Errorf("get map (native) heap: %w", err)
	}

	stackCountNative, err := m.nativeModule.GetMap(StackCountsMapName)
	if err != nil {
		return fmt.Errorf("get map (native) stack_counts: %w", err)
	}

	interpStacksNative, err := m.nativeModule.GetMap(InterpreterStackTracesMapName)
	if err != nil {
		return fmt.Errorf("get map (native) interpreter_stack_traces: %w", err)
	}

	symbolIndexStorage, err := m.nativeModule.GetMap(SymbolIndexStorageMapName)
	if err != nil {
		return fmt.Errorf("get map (native) symbol_index_storage map: %w", err)
	}

	symbolTableMap, err := m.nativeModule.GetMap(SymbolTableMapName)
	if err != nil {
		return fmt.Errorf("get map (native) symbol_table map: %w", err)
	}

	if m.rbperfModule != nil {
		// Fetch rbperf maps.
		rubyHeap, err := m.rbperfModule.GetMap(HeapMapName)
		if err != nil {
			return (fmt.Errorf("get map (rbperf) heap: %w", err))
		}
		rubystackCounts, err := m.rbperfModule.GetMap(StackCountsMapName)
		if err != nil {
			return fmt.Errorf("get map (rbperf) stack_counts: %w", err)
		}
		rubyInterpreterStacks, err := m.rbperfModule.GetMap(InterpreterStackTracesMapName)
		if err != nil {
			return fmt.Errorf("get map (rbperf) interpreter_stack_traces: %w", err)
		}
		rubySymbolIndex, err := m.rbperfModule.GetMap(SymbolIndexStorageMapName)
		if err != nil {
			return fmt.Errorf("get map (rbperf) symbol_index_storage: %w", err)
		}
		rubySymbolTable, err := m.rbperfModule.GetMap(SymbolTableMapName)
		if err != nil {
			return fmt.Errorf("get map (rbperf) symbol_table: %w", err)
		}

		// Reuse maps across programs.
		err = rubyHeap.ReuseFD(heapNative.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (rbperf) heap: %w", err)
		}
		err = rubystackCounts.ReuseFD(stackCountNative.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (rbperf) stack_counts: %w", err)
		}
		err = rubyInterpreterStacks.ReuseFD(interpStacksNative.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (rbperf) interpreter_stack_traces: %w", err)
		}
		err = rubySymbolIndex.ReuseFD(symbolIndexStorage.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (rbperf) symbol_index_storage: %w", err)
		}
		err = rubySymbolTable.ReuseFD(symbolTableMap.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (rbperf) symbol_table: %w", err)
		}
	}

	if m.pyperfModule != nil {
		// Fetch pyperf maps.
		pythonHeap, err := m.pyperfModule.GetMap(HeapMapName)
		if err != nil {
			return fmt.Errorf("get map (pyperf) heap: %w", err)
		}
		pythonStackCounts, err := m.pyperfModule.GetMap(StackCountsMapName)
		if err != nil {
			return fmt.Errorf("get map (pyperf) stack_counts: %w", err)
		}
		pythonInterpreterStacks, err := m.pyperfModule.GetMap(InterpreterStackTracesMapName)
		if err != nil {
			return fmt.Errorf("get map (pyperf) interpreter_stack_traces: %w", err)
		}
		pythonSymbolIndex, err := m.pyperfModule.GetMap(SymbolIndexStorageMapName)
		if err != nil {
			return fmt.Errorf("get map (pyperf) symbol_index_storage: %w", err)
		}
		pythonSymbolTable, err := m.pyperfModule.GetMap(SymbolTableMapName)
		if err != nil {
			return fmt.Errorf("get map (pyperf) symbol_table: %w", err)
		}

		// Reuse maps across programs.
		err = pythonHeap.ReuseFD(heapNative.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (pyperf) heap: %w", err)
		}
		err = pythonStackCounts.ReuseFD(stackCountNative.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (pyperf) stack_counts: %w", err)
		}
		err = pythonInterpreterStacks.ReuseFD(interpStacksNative.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (pyperf) interpreter_stack_traces: %w", err)
		}
		err = pythonSymbolIndex.ReuseFD(symbolIndexStorage.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (pyperf) symbol_index_storage: %w", err)
		}
		err = pythonSymbolTable.ReuseFD(symbolTableMap.FileDescriptor())
		if err != nil {
			return fmt.Errorf("reuse map (pyperf) symbol_table: %w", err)
		}
	}

	return nil
}

// Interpreter Information.

// TODO(kakkoyun): DRY. Move.
func (m *Maps) setRbperfProcessData(pid int, procData rbperf.ProcessData) error {
	if m.rbperfModule == nil {
		return nil
	}

	pidToRbData, err := m.rbperfModule.GetMap(RubyPIDToRubyThreadMapName)
	if err != nil {
		return fmt.Errorf("get map pid_to_rb_thread: %w", err)
	}

	buf := new(bytes.Buffer)
	buf.Grow(int(unsafe.Sizeof(&procData)))

	err = binary.Write(buf, binary.LittleEndian, &procData)
	if err != nil {
		return fmt.Errorf("write procData to buffer: %w", err)
	}

	pidToRbDataKey := uint32(pid)
	err = pidToRbData.Update(unsafe.Pointer(&pidToRbDataKey), unsafe.Pointer(&buf.Bytes()[0]))
	if err != nil {
		return fmt.Errorf("update map pid_to_rb_thread: %w", err)
	}
	return nil
}

// TODO(kakkoyun): DRY. Move.
func (m *Maps) setRbperfVersionOffsets(versionOffsets rbperf.RubyVersionOffsets) error {
	if m.rbperfModule == nil {
		return nil
	}

	versions, err := m.rbperfModule.GetMap(RubyVersionSpecificOffsetMapName)
	if err != nil {
		return fmt.Errorf("get map version_specific_offsets: %w", err)
	}

	buf := new(bytes.Buffer)
	buf.Grow(int(unsafe.Sizeof(&versionOffsets)))

	err = binary.Write(buf, binary.LittleEndian, &versionOffsets)
	if err != nil {
		return fmt.Errorf("write versionOffsets to buffer: %w", err)
	}

	key := uint32(0)
	err = versions.Update(unsafe.Pointer(&key), unsafe.Pointer(&buf.Bytes()[0]))
	if err != nil {
		return fmt.Errorf("update map version_specific_offsets: %w", err)
	}
	return nil
}

// TODO(kakkoyun): DRY. Move.
func (m *Maps) setPyperfIntepreterInfo(pid int, interpInfo pyperf.InterpreterInfo) error {
	if m.pyperfModule == nil {
		return nil
	}
	pidToInterpreterInfo, err := m.pyperfModule.GetMap(PythonPIDToInterpreterInfoMapName)
	if err != nil {
		return fmt.Errorf("get map pid_to_interpreter_info: %w", err)
	}

	buf := new(bytes.Buffer)
	buf.Grow(int(unsafe.Sizeof(&interpInfo)))

	err = binary.Write(buf, binary.LittleEndian, &interpInfo)
	if err != nil {
		return fmt.Errorf("write interpreter info to buffer: %w", err)
	}

	pidToProcInfoKey := uint32(pid)
	err = pidToInterpreterInfo.Update(unsafe.Pointer(&pidToProcInfoKey), unsafe.Pointer(&buf.Bytes()[0]))
	if err != nil {
		return fmt.Errorf("update map pid_to_interpreter_info: %w", err)
	}
	return nil
}

// TODO(kakkoyun): DRY. Move.
func (m *Maps) setPyperfVersionOffsets(versionOffsets []python.VersionOffsets) error {
	if m.pyperfModule == nil {
		return nil
	}
	versions, err := m.pyperfModule.GetMap(PythonVersionSpecificOffsetMapName)
	if err != nil {
		return fmt.Errorf("get map version_specific_offsets: %w", err)
	}

	if len(versionOffsets) == 0 {
		return fmt.Errorf("no version offsets provided")
	}

	buf := new(bytes.Buffer)
	i := uint32(0)
	for _, v := range versionOffsets {
		buf.Grow(int(unsafe.Sizeof(&v)))
		err = binary.Write(buf, binary.LittleEndian, &v)
		if err != nil {
			level.Debug(m.logger).Log("msg", "write versionOffsets to buffer", "err", err)
			continue
		}
		key := i
		err = versions.Update(unsafe.Pointer(&key), unsafe.Pointer(&buf.Bytes()[0]))
		if err != nil {
			level.Debug(m.logger).Log("msg", "update map version_specific_offsets", "err", err)
			continue
		}
		m.pythonVersionToOffsetIndex[fmt.Sprintf("%d.%d", v.MajorVersion, v.MinorVersion)] = i
		i++
		buf.Reset()
	}
	return nil
}

// TODO(javierhonduco): Add all the supported Ruby versions.
func (m *Maps) SetInterpreterData() error {
	if m.pyperfModule == nil && m.rbperfModule == nil {
		return nil
	}

	symbolIndexStorage, err := m.nativeModule.GetMap(SymbolIndexStorageMapName)
	if err != nil {
		return fmt.Errorf("get symbol_index_storage map: %w", err)
	}

	key := uint32(0)
	value := uint64(1)
	err = symbolIndexStorage.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		return fmt.Errorf("update symbol_index_storage map: %w", err)
	}

	if m.rbperfModule != nil {
		err = m.setRbperfVersionOffsets(rbperf.RubyVersionOffsets{
			MajorVersion:        3,
			MinorVersion:        0,
			PatchVersion:        4,
			VMOffset:            0,
			VMSizeOffset:        8,
			ControlFrameSizeof:  56,
			CfpOffset:           16,
			LabelOffset:         16,
			PathFlavour:         1,
			LineInfoSizeOffset:  136,
			LineInfoTableOffset: 120,
			LinenoOffset:        0,
			MainThreadOffset:    32,
			EcOffset:            520,
		})
		if err != nil {
			return fmt.Errorf("set rbperf version offsets: %w", err)
		}
	}

	if m.pyperfModule != nil {
		versions, err := python.GetVersions()
		if err != nil {
			return fmt.Errorf("get python versions: %w", err)
		}

		err = m.setPyperfVersionOffsets(versions)
		if err != nil {
			return fmt.Errorf("set pyperf version offsets: %w", err)
		}
	}

	return nil
}

func (m *Maps) UpdateTailCallsMap() error {
	if m.pyperfModule == nil && m.rbperfModule == nil {
		return nil
	}

	entrypointPrograms, err := m.nativeModule.GetMap(ProgramsMapName)
	if err != nil {
		return fmt.Errorf("get map (native) programs: %w", err)
	}

	if m.rbperfModule != nil {
		// rbperf.
		rubyEntrypointProg, err := m.rbperfModule.GetProgram("unwind_ruby_stack")
		if err != nil {
			return fmt.Errorf("get program unwind_ruby_stack: %w", err)
		}

		rubyEntrypointFd := rubyEntrypointProg.FileDescriptor()
		if err = entrypointPrograms.Update(unsafe.Pointer(&bpfprograms.RubyEntrypointProgramFD), unsafe.Pointer(&rubyEntrypointFd)); err != nil {
			return fmt.Errorf("update (native) programs: %w", err)
		}

		rubyWalkerProg, err := m.rbperfModule.GetProgram("walk_ruby_stack")
		if err != nil {
			return fmt.Errorf("get program walk_ruby_stack: %w", err)
		}

		rubyPrograms, err := m.rbperfModule.GetMap(ProgramsMapName)
		if err != nil {
			return fmt.Errorf("get map (rbperf) programs: %w", err)
		}

		rubyWalkerFd := rubyWalkerProg.FileDescriptor()
		if err = rubyPrograms.Update(unsafe.Pointer(&bpfprograms.RubyUnwinderProgramFD), unsafe.Pointer(&rubyWalkerFd)); err != nil {
			return fmt.Errorf("update (rbperf) programs: %w", err)
		}
	}

	if m.pyperfModule != nil {
		// pyperf.
		pythonEntrypointProg, err := m.pyperfModule.GetProgram("unwind_python_stack")
		if err != nil {
			return fmt.Errorf("get program unwind_python_stack: %w", err)
		}

		pythonEntrypointFd := pythonEntrypointProg.FileDescriptor()
		if err = entrypointPrograms.Update(unsafe.Pointer(&bpfprograms.PythonEntrypointProgramFD), unsafe.Pointer(&pythonEntrypointFd)); err != nil {
			return fmt.Errorf("update (native) programs: %w", err)
		}

		pythonWalkerProg, err := m.pyperfModule.GetProgram("walk_python_stack")
		if err != nil {
			return fmt.Errorf("get program walk_python_stack: %w", err)
		}

		pythonPrograms, err := m.pyperfModule.GetMap(ProgramsMapName)
		if err != nil {
			return fmt.Errorf("get map (pyperf) programs: %w", err)
		}

		pythonWalkerFd := pythonWalkerProg.FileDescriptor()
		if err = pythonPrograms.Update(unsafe.Pointer(&bpfprograms.PythonUnwinderProgramFD), unsafe.Pointer(&pythonWalkerFd)); err != nil {
			return fmt.Errorf("update (pyperf) programs: %w", err)
		}
	}

	return nil
}

// Close closes all the resources associated with the maps.
func (m *Maps) Close() error {
	return m.processCache.close()
}

// AdjustMapSizes updates the amount of unwind shards.
//
// Note: It must be called before `BPFLoadObject()`.
func (m *Maps) AdjustMapSizes(debugEnabled bool, unwindTableShards, eventsBufferSize uint32) error {
	unwindTables, err := m.nativeModule.GetMap(UnwindTablesMapName)
	if err != nil {
		return fmt.Errorf("get unwind tables map: %w", err)
	}

	// Adjust unwind_tables size.
	sizeBefore := unwindTables.MaxEntries()
	if err := unwindTables.SetMaxEntries(unwindTableShards); err != nil {
		return fmt.Errorf("resize unwind tables map from %d to %d elements: %w", sizeBefore, unwindTableShards, err)
	}

	m.maxUnwindShards = uint64(unwindTableShards)

	if m.pyperfModule != nil || m.rbperfModule != nil {
		symbolTable, err := m.nativeModule.GetMap(SymbolTableMapName)
		if err != nil {
			return fmt.Errorf("get symbol table map: %w", err)
		}

		// Adjust symbol_table size.
		if err := symbolTable.SetMaxEntries(defaultSymbolTableSize); err != nil {
			return fmt.Errorf("resize symbol table map from default to %d elements: %w", unwindTableShards, err)
		}
	}

	// Adjust events size.
	eventCounts, err := m.nativeModule.GetMap(eventsMapName)
	if err != nil {
		return fmt.Errorf("get event map: %w", err)
	}
	if err := eventCounts.SetMaxEntries(eventsBufferSize); err != nil {
		return fmt.Errorf("resize event map from default to %d elements: %w", maxProcesses, err)
	}

	// Adjust debug_pids size.
	if debugEnabled {
		debugPIDs, err := m.nativeModule.GetMap(DebugPIDsMapName)
		if err != nil {
			return fmt.Errorf("get debug pids map: %w", err)
		}
		if err := debugPIDs.SetMaxEntries(maxProcesses); err != nil {
			return fmt.Errorf("resize debug pids map from default to %d elements: %w", maxProcesses, err)
		}
	}
	return nil
}

func (m *Maps) Create() error {
	debugPIDs, err := m.nativeModule.GetMap(DebugPIDsMapName)
	if err != nil {
		return fmt.Errorf("get debug pids map: %w", err)
	}

	stackCounts, err := m.nativeModule.GetMap(StackCountsMapName)
	if err != nil {
		return fmt.Errorf("get counts map: %w", err)
	}

	eventsCount, err := m.nativeModule.GetMap(eventsCountMapName)
	if err != nil {
		return fmt.Errorf("get events count map: %w", err)
	}

	stackTraces, err := m.nativeModule.GetMap(StackTracesMapName)
	if err != nil {
		return fmt.Errorf("get stack traces map: %w", err)
	}

	unwindShards, err := m.nativeModule.GetMap(UnwindInfoChunksMapName)
	if err != nil {
		return fmt.Errorf("get unwind shards map: %w", err)
	}

	unwindTables, err := m.nativeModule.GetMap(UnwindTablesMapName)
	if err != nil {
		return fmt.Errorf("get unwind tables map: %w", err)
	}

	dwarfStackTraces, err := m.nativeModule.GetMap(DWARFStackTracesMapName)
	if err != nil {
		return fmt.Errorf("get dwarf stack traces map: %w", err)
	}

	processInfo, err := m.nativeModule.GetMap(ProcessInfoMapName)
	if err != nil {
		return fmt.Errorf("get process info map: %w", err)
	}

	m.debugPIDs = debugPIDs
	m.StackCounts = stackCounts
	m.stackTraces = stackTraces
	m.eventsCount = eventsCount
	m.unwindShards = unwindShards
	m.unwindTables = unwindTables
	m.dwarfStackTraces = dwarfStackTraces
	m.processInfo = processInfo

	if m.pyperfModule == nil && m.rbperfModule == nil {
		return nil
	}

	interpreterStackTraces, err := m.nativeModule.GetMap(InterpreterStackTracesMapName)
	if err != nil {
		return fmt.Errorf("get dwarf stack traces map: %w", err)
	}

	symbolTable, err := m.nativeModule.GetMap(SymbolTableMapName)
	if err != nil {
		return fmt.Errorf("get symbol table map: %w", err)
	}

	m.interpreterStackTraces = interpreterStackTraces
	m.symbolTable = symbolTable

	if m.rbperfModule != nil {
		// rbperf maps.
		rubyPIDToRubyThread, err := m.rbperfModule.GetMap(RubyPIDToRubyThreadMapName)
		if err != nil {
			return fmt.Errorf("get pid to rb thread map: %w", err)
		}

		rubyVersionSpecificOffsets, err := m.rbperfModule.GetMap(RubyVersionSpecificOffsetMapName)
		if err != nil {
			return fmt.Errorf("get pid to rb thread map: %w", err)
		}

		// rbperf maps.
		m.rubyPIDToThread = rubyPIDToRubyThread
		m.rubyVersionSpecificOffsets = rubyVersionSpecificOffsets
	}

	if m.pyperfModule != nil {
		pythonPIDToProcessInfo, err := m.pyperfModule.GetMap(PythonPIDToInterpreterInfoMapName)
		if err != nil {
			return fmt.Errorf("get pid to process info map: %w", err)
		}

		pythonVersionSpecificOffsets, err := m.pyperfModule.GetMap(PythonVersionSpecificOffsetMapName)
		if err != nil {
			return fmt.Errorf("get pid to process info map: %w", err)
		}

		// pyperf maps.
		m.pythonPIDToProcessInfo = pythonPIDToProcessInfo
		m.pythonVersionSpecificOffsets = pythonVersionSpecificOffsets
	}

	return nil
}

func (m *Maps) AddInterpreter(pid int, interpreter runtime.Interpreter) error {
	switch interpreter.Type {
	case runtime.InterpreterRuby:
		procData := rbperf.ProcessData{
			RbFrameAddr: interpreter.MainThreadAddress,
			RbVersion:   m.indexForRubyVersion(interpreter.Version),
			Padding_:    [4]byte{0, 0, 0, 0},
			StartTime:   0, // Unused as of now.
		}
		return m.setRbperfProcessData(pid, procData)
	case runtime.InterpreterPython:
		i, err := m.indexForPythonVersion(interpreter.Version)
		if err != nil {
			return fmt.Errorf("index for python version: %w", err)
		}
		interpreterInfo := pyperf.InterpreterInfo{
			ThreadStateAddr:      interpreter.MainThreadAddress,
			PyVersionOffsetIndex: i,
		}
		level.Debug(m.logger).Log("msg", "Python Version Offset", "pid", pid, "version_offset_index", i)
		return m.setPyperfIntepreterInfo(pid, interpreterInfo)
	default:
		return fmt.Errorf("invalid interpreter name: %d", interpreter.Type)
	}
}

// TODO(javierhonduco): Add support for all the Ruby versions.
func (m *Maps) indexForRubyVersion(version *semver.Version) uint32 {
	return 0
}

func (m *Maps) indexForPythonVersion(version *semver.Version) (uint32, error) {
	if i, ok := m.pythonVersionToOffsetIndex[fmt.Sprintf("%d.%d", version.Major(), version.Minor())]; ok {
		return i, nil
	}
	return 0, errors.New("unknown Python Version")
}

func (m *Maps) SetDebugPIDs(pids []int) error {
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

// ReadUserStack reads the user stack trace from the stacktraces ebpf map into the given buffer.
func (m *Maps) ReadUserStack(userStackID int32, stack *bpfprograms.CombinedStack) error {
	if userStackID == 0 {
		return ErrUnwindFailed
	}

	stackBytes, err := m.stackTraces.GetValue(unsafe.Pointer(&userStackID))
	if err != nil {
		return fmt.Errorf("read user stack trace, %w: %w", err, ErrMissing)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, stack[:bpfprograms.StackDepth]); err != nil {
		return fmt.Errorf("read user stack bytes, %w: %w", err, ErrUnrecoverable)
	}

	return nil
}

// ReadUserStackWithDwarf reads the DWARF walked user stack traces into the given buffer.
func (m *Maps) ReadUserStackWithDwarf(userStackID int32, stack *bpfprograms.CombinedStack) error {
	if userStackID == 0 {
		return ErrUnwindFailed
	}

	type dwarfStacktrace struct {
		Len   uint64
		Addrs [bpfprograms.StackDepth]uint64
	}

	stackBytes, err := m.dwarfStackTraces.GetValue(unsafe.Pointer(&userStackID))
	if err != nil {
		return fmt.Errorf("read user stack trace, %w: %w", err, ErrMissing)
	}

	var dwarfStack dwarfStacktrace
	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, &dwarfStack); err != nil {
		return fmt.Errorf("read user stack bytes, %w: %w", err, ErrUnrecoverable)
	}

	userStack := stack[:bpfprograms.StackDepth]

	for i, addr := range dwarfStack.Addrs {
		if i >= bpfprograms.StackDepth || i >= int(dwarfStack.Len) || addr == 0 {
			break
		}
		userStack[i] = addr
	}

	return nil
}

// cStringToGo converts a C string in a buffer to a Go string,
// making sure we do not read past NUL, as this is a statically
// sized buffer that might not be full.
func cStringToGo(in []uint8) string {
	var buffer bytes.Buffer
	for _, datum := range in {
		if datum == 0 {
			break
		}
		buffer.WriteByte(datum)
	}
	return buffer.String()
}

// ReadInterpreterStack fills in the stack with the interpreter frame ids.
func (m *Maps) ReadInterpreterStack(interpreterStackID int32, stack []uint64) (map[uint32]*profile.Function, error) {
	var res map[uint32]*profile.Function

	if interpreterStackID == 0 {
		return res, ErrUnwindFailed
	}

	type dwarfStacktrace struct {
		Len   uint64
		Addrs [bpfprograms.StackDepth]uint64
	}

	stackBytes, err := m.interpreterStackTraces.GetValue(unsafe.Pointer(&interpreterStackID))
	if err != nil {
		return res, fmt.Errorf("read interpreter stack trace, %w: %w", err, ErrMissing)
	}

	var interpreterStack dwarfStacktrace
	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, &interpreterStack); err != nil {
		return res, fmt.Errorf("read interpreter stack bytes, %w: %w", err, ErrUnrecoverable)
	}

	res, err = m.interpreterSymbolTable()
	if err != nil {
		return res, fmt.Errorf("readAllInterpreterFrames: %w", err)
	}

	for i, frameID := range interpreterStack.Addrs {
		if i >= bpfprograms.StackDepth || i >= int(interpreterStack.Len) {
			break
		}
		stack[i] = frameID
	}

	return res, nil
}

// interpreterSymbolTable retrieves the whole symbol table in full so we
// can construct a fast frameId -> Frame lookup table.

// PERF: This code presents (at least) presents two possible performance
// opportunities that we should measure.
//
// - Preallocating the lookup table.
// - Batch the BPF map calls to read and update them.
func (m *Maps) interpreterSymbolTable() (map[uint32]*profile.Function, error) {
	interpreterFrames := make(map[uint32]*profile.Function, 0)

	symbolTable, err := m.nativeModule.GetMap(SymbolTableMapName)
	if err != nil {
		return interpreterFrames, fmt.Errorf("get frame table map: %w", err)
	}

	it := symbolTable.Iterator()
	for it.Next() {
		keyBytes := it.Key()
		symbol := bpf.Symbol{}
		if err := binary.Read(bytes.NewBuffer(keyBytes), m.byteOrder, &symbol); err != nil {
			return interpreterFrames, fmt.Errorf("read interpreter stack bytes, %w: %w", err, ErrUnrecoverable)
		}

		valBytes, err := symbolTable.GetValue(unsafe.Pointer(&keyBytes[0]))
		if err != nil {
			return interpreterFrames, fmt.Errorf("read interpreter val bytes, %w: %w", err, ErrUnrecoverable)
		}

		symbolIndex := uint32(0)
		if err := binary.Read(bytes.NewBuffer(valBytes), m.byteOrder, &symbolIndex); err != nil {
			return interpreterFrames, fmt.Errorf("read interpreter frame bytes, %w: %w", err, ErrUnrecoverable)
		}
		interpreterFrames[symbolIndex] = &profile.Function{
			ModuleName: cStringToGo(symbol.ClassName[:]),
			Name:       cStringToGo(symbol.MethodName[:]),
			Filename:   cStringToGo(symbol.Path[:]),
			StartLine:  int(symbol.Lineno),
		}
	}

	return interpreterFrames, nil
}

// ReadKernelStack reads the kernel stack trace from the stacktraces ebpf map into the given buffer.
func (m *Maps) ReadKernelStack(kernelStackID int32, stack *bpfprograms.CombinedStack) error {
	if kernelStackID == 0 {
		return ErrUnwindFailed
	}

	stackBytes, err := m.stackTraces.GetValue(unsafe.Pointer(&kernelStackID))
	if err != nil {
		return fmt.Errorf("read kernel stack trace, %w: %w", err, ErrMissing)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), m.byteOrder, stack[bpfprograms.StackDepth:bpfprograms.StackDepth*2]); err != nil {
		return fmt.Errorf("read kernel stack bytes, %w: %w", err, ErrUnrecoverable)
	}

	return nil
}

// ReadStackCount reads the value of the given key from the counts ebpf map.
func (m *Maps) ReadStackCount(keyBytes []byte) (uint64, error) {
	valueBytes, err := m.StackCounts.GetValue(unsafe.Pointer(&keyBytes[0]))
	if err != nil {
		return 0, fmt.Errorf("get count value: %w", err)
	}
	return m.byteOrder.Uint64(valueBytes), nil
}

func (m *Maps) FinalizeProfileLoop() error {
	m.profilingRoundsWithoutUnwindInfoReset++
	m.profilingRoundsWithoutProcessInfoReset++

	var result error

	if err := m.cleanStacks(); err != nil {
		result = errors.Join(result, err)
	}

	if err := m.cleanEventsCount(); err != nil {
		result = errors.Join(result, err)
	}

	return result
}

func (m *Maps) cleanStacks() error {
	var result error

	if err := clearMap(m.stackTraces); err != nil {
		m.metrics.mapCleanErrors.WithLabelValues(m.stackTraces.Name()).Inc()
		result = errors.Join(result, err)
	}

	if err := clearMap(m.dwarfStackTraces); err != nil {
		m.metrics.mapCleanErrors.WithLabelValues(m.dwarfStackTraces.Name()).Inc()
		result = errors.Join(result, err)
	}

	if err := clearMap(m.StackCounts); err != nil {
		m.metrics.mapCleanErrors.WithLabelValues(m.StackCounts.Name()).Inc()
		result = errors.Join(result, err)
	}

	return result
}

func clearMap(bpfMap *libbpf.BPFMap) error {
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

func (m *Maps) cleanEventsCount() error {
	if err := clearMap(m.eventsCount); err != nil {
		m.metrics.mapCleanErrors.WithLabelValues(m.eventsCount.Name()).Inc()
		return err
	}
	return nil
}

func (m *Maps) cleanProcessInfo() error {
	if err := clearMap(m.processInfo); err != nil {
		m.metrics.mapCleanErrors.WithLabelValues(m.processInfo.Name()).Inc()
		return err
	}
	return nil
}

func (m *Maps) cleanShardInfo() error {
	// unwindShards
	if err := clearMap(m.unwindShards); err != nil {
		m.metrics.mapCleanErrors.WithLabelValues(m.unwindShards.Name()).Inc()
		return err
	}
	return nil
}

func (m *Maps) resetMappingInfoBuffer() error {
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

// RefreshProcessInfo updates the process information such as mappings and unwind
// information if the executable mappings have changed.
func (m *Maps) RefreshProcessInfo(pid int, interp *runtime.Interpreter) {
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
		m.metrics.refreshProcessInfoErrors.WithLabelValues(labelHash).Inc()
		level.Error(m.logger).Log("msg", "executableMappings hash failed", "err", err)
		return
	}

	if cachedHash != currentHash {
		err := m.AddUnwindTableForProcess(pid, interp, executableMappings, false)
		if err != nil {
			m.metrics.refreshProcessInfoErrors.WithLabelValues(labelUnwindTableAdd).Inc()
			level.Error(m.logger).Log("msg", "addUnwindTableForProcess failed", "err", err)
		}
	}
}

// 1. Find executable sections
// 2. For each section, generate compact table
// 3. Add table to maps
// 4. Add map metadata to process
func (m *Maps) AddUnwindTableForProcess(pid int, interp *runtime.Interpreter, executableMappings unwind.ExecutableMappings, checkCache bool) error {
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
	var isJitCompiler uint64
	if executableMappings.HasJitted() {
		isJitCompiler = 1
	}

	if len(executableMappings) >= maxMappingsPerProcess {
		return ErrTooManyExecutableMappings
	}

	mappingInfoMemory := m.mappingInfoMemory.Slice(mappingInfoSizeBytes)
	// .is_jit_compiler
	mappingInfoMemory.PutUint64(isJitCompiler)
	// .interpreter_type
	var interpreterType uint64
	if interp != nil {
		interpreterType = uint64(interp.Type)
	}

	mappingInfoMemory.PutUint64(interpreterType)
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
			level.Debug(m.logger).Log("msg", "resetting process information", "cleanErr", cleanErr)

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

// writeUnwindTableRow writes a compact unwind table row to the provided slice.
//
// Note: we are avoiding `binary.Write` and prefer to use the lower level APIs
// to avoid allocations and CPU spent in the reflection code paths as well as
// in the allocations for the intermediate buffers.
func (m *Maps) writeUnwindTableRow(rowSlice *profiler.EfficientBuffer, row unwind.CompactUnwindTableRow, arch elf.Machine) {
	// .pc
	rowSlice.PutUint64(row.Pc())
	if arch == elf.EM_AARCH64 {
		// .lr_offset
		rowSlice.PutInt16(row.LrOffset())
	}
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
func (m *Maps) writeMapping(buf *profiler.EfficientBuffer, loadAddress, startAddr, endAddr, executableID, type_ uint64) {
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
func (m *Maps) mappingID(buildID string) (uint64, bool) {
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
func (m *Maps) resetInFlightBuffer() error {
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
func (m *Maps) PersistUnwindTable() error {
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
func (m *Maps) persistUnwindTable() error {
	totalRows := len(m.unwindInfoMemory) / m.compactUnwindRowSizeBytes
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

func (m *Maps) resetUnwindState() error {
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
func (m *Maps) availableEntries() uint64 {
	return maxUnwindTableSize - m.highIndex
}

// assertInvariants checks that some invariants that should
// always be true during the execution of the program are held.
func (m *Maps) assertInvariants() {
	if m.highIndex > maxUnwindTableSize {
		panic(fmt.Sprintf("m.highIndex (%d)> 250k, this should never happen", m.highIndex))
	}
	tableSize := len(m.unwindInfoMemory) / m.compactUnwindRowSizeBytes
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
func (m *Maps) allocateNewShard() error {
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
func (m *Maps) setUnwindTableForMapping(buf *profiler.EfficientBuffer, pid int, mapping *unwind.ExecutableMapping) error {
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
		ut, arch, err := unwind.GenerateCompactUnwindTable(fullExecutablePath, mapping.Executable)
		level.Debug(m.logger).Log("msg", "found unwind entries", "executable", mapping.Executable, "len", len(ut))

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
				level.Error(m.logger).Log("msg", "first row of a chunk should not be a marker")
			}

			if !currentChunk[len(currentChunk)-1].IsEndOfFDEMarker() {
				level.Error(m.logger).Log("msg", "last row of a chunk should always be a marker")
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
				rowSlice := m.unwindInfoMemory.Slice(m.compactUnwindRowSizeBytes)
				m.writeUnwindTableRow(&rowSlice, row, arch)
			}

			// We ran out of space in the current shard. Let's allocate a new one.
			if m.availableEntries() == 0 {
				level.Debug(m.logger).Log("msg", "creating a new shard as we ran out of space")

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
