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
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	debugPIDsMapName        = "debug_pids"
	stackCountsMapName      = "stack_counts"
	stackTracesMapName      = "stack_traces"
	dwarfStackTracesMapName = "dwarf_stack_traces"
	unwindTablesMapName     = "unwind_tables"
	programsMapName         = "programs"

	// With the current row structure, the max items we can store is 262k per map.
	unwindTableMaxEntries = 100
	maxUnwindTableSize    = 250 * 1000 // Always needs to be sync with MAX_UNWIND_TABLE_SIZE in the BPF program.
	unwindTableShardCount = 6          // Always needs to be sync with MAX_SHARDS in the BPF program.
	maxUnwindSize         = maxUnwindTableSize * unwindTableShardCount
)

type BpfCfaType uint16

const (
	CfaRegisterUndefined BpfCfaType = iota
	CfaRegisterRbp
	CfaRegisterRsp
	CfaRegisterExpression
)

type BpfRbpType uint16

const (
	RbpRuleOffsetUnchanged BpfRbpType = iota
	RbpRuleOffset
	RbpRuleRegister
	RbpRegisterExpression
)

var (
	errMissing       = errors.New("missing stack trace")
	errUnwindFailed  = errors.New("stack ID is 0, probably stack unwinding failed")
	errUnrecoverable = errors.New("unrecoverable error")
)

type bpfMaps struct {
	module    *bpf.Module
	pool      sync.Pool
	byteOrder binary.ByteOrder

	debugPIDs *bpf.BPFMap

	stackCounts      *bpf.BPFMap
	stackTraces      *bpf.BPFMap
	dwarfStackTraces *bpf.BPFMap

	unwindTables *bpf.BPFMap
	programs     *bpf.BPFMap
}

func initializeMaps(m *bpf.Module, byteOrder binary.ByteOrder) (*bpfMaps, error) {
	if m == nil {
		return nil, fmt.Errorf("nil module")
	}

	maps := &bpfMaps{
		module: m,
		pool: sync.Pool{New: func() interface{} {
			return &bytes.Buffer{}
		}},
		byteOrder: byteOrder,
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

	unwindTables, err := m.module.GetMap(unwindTablesMapName)
	if err != nil {
		return fmt.Errorf("get unwind tables map: %w", err)
	}

	dwarfStackTraces, err := m.module.GetMap(dwarfStackTracesMapName)
	if err != nil {
		return fmt.Errorf("get dwarf stack traces map: %w", err)
	}

	m.debugPIDs = debugPIDs
	m.stackCounts = stackCounts
	m.stackTraces = stackTraces
	m.unwindTables = unwindTables
	m.dwarfStackTraces = dwarfStackTraces
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

	it = m.stackCounts.Iterator()
	prev = nil
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

	return nil
}

// setUnwindTable updates the unwind tables with the given unwind table.
func (m *bpfMaps) setUnwindTable(pid int, ut unwind.UnwindTable) error {
	buf := m.pool.Get().(*bytes.Buffer)
	keyBuf := m.pool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		keyBuf.Reset()
		m.pool.Put(buf)
		m.pool.Put(keyBuf)
	}()

	if len(ut) >= maxUnwindSize {
		return fmt.Errorf("maximum unwind table size reached. Table size %d, but max size is %d", len(ut), maxUnwindSize)
	}

	// Range-partition the unwind table in the different shards.
	shardIndex := 0
	for i := 0; i < len(ut); i += maxUnwindTableSize {
		upTo := i + maxUnwindTableSize
		if upTo > len(ut) {
			upTo = len(ut)
		}

		chunk := ut[i:upTo]

		// Write `.low_pc`
		if err := binary.Write(buf, m.byteOrder, chunk[0].Loc); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		// Write `.high_pc`.
		if err := binary.Write(buf, m.byteOrder, chunk[len(chunk)-1].Loc); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		// Write number of rows `.table_len`.
		if err := binary.Write(buf, m.byteOrder, uint64(len(chunk))); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		// Write padding.
		if err := binary.Write(buf, m.byteOrder, uint64(0)); err != nil {
			return fmt.Errorf("write the number of rows: %w", err)
		}
		for _, row := range chunk {
			// Right now we only support x86_64, where the return address position
			// is specified in the ABI, so we don't write it.

			// Write Program Counter (PC).
			if err := binary.Write(buf, m.byteOrder, row.Loc); err != nil {
				return fmt.Errorf("write the program counter: %w", err)
			}

			// Write __reserved_do_not_use.
			if err := binary.Write(buf, m.byteOrder, uint16(0)); err != nil {
				return fmt.Errorf("write CFA register bytes: %w", err)
			}

			var CfaRegister uint8
			var RbpRegister uint8
			var CfaOffset int16
			var RbpOffset int16

			// CFA.
			switch row.CFA.Rule {
			case frame.RuleCFA:
				if row.CFA.Reg == frame.X86_64FramePointer {
					CfaRegister = uint8(CfaRegisterRbp)
				} else if row.CFA.Reg == frame.X86_64StackPointer {
					CfaRegister = uint8(CfaRegisterRsp)
				}
				CfaOffset = int16(row.CFA.Offset)
			case frame.RuleExpression:
				CfaRegister = uint8(CfaRegisterExpression)
				CfaOffset = int16(unwind.ExpressionIdentifier(row.CFA.Expression))

			default:
				return fmt.Errorf("CFA rule is not valid. This should never happen")
			}

			// Frame pointer.
			switch row.RBP.Rule {
			case frame.RuleUndefined:
			case frame.RuleOffset:
				RbpRegister = uint8(RbpRuleOffset)
				RbpOffset = int16(row.RBP.Offset)
			case frame.RuleRegister:
				RbpRegister = uint8(RbpRuleRegister)
			case frame.RuleExpression:
				RbpRegister = uint8(RbpRegisterExpression)
			}

			// Write CFA type (.cfa_type).
			if err := binary.Write(buf, m.byteOrder, CfaRegister); err != nil {
				return fmt.Errorf("write CFA register bytes: %w", err)
			}

			// Write frame pointer type (.rbp_type).
			if err := binary.Write(buf, m.byteOrder, RbpRegister); err != nil {
				return fmt.Errorf("write CFA register bytes: %w", err)
			}

			// Write CFA offset (.cfa_offset).
			if err := binary.Write(buf, m.byteOrder, CfaOffset); err != nil {
				return fmt.Errorf("write CFA offset bytes: %w", err)
			}

			// Write frame pointer offset (.rbp_offset).
			if err := binary.Write(buf, m.byteOrder, RbpOffset); err != nil {
				return fmt.Errorf("write RBP offset bytes: %w", err)
			}
		}

		// Set (PID, shard ID) -> unwind table for each shard.
		if err := binary.Write(keyBuf, m.byteOrder, int32(pid)); err != nil {
			return fmt.Errorf("write RBP offset bytes: %w", err)
		}
		if err := binary.Write(keyBuf, m.byteOrder, int32(shardIndex)); err != nil {
			return fmt.Errorf("write RBP offset bytes: %w", err)
		}

		err := m.unwindTables.Update(
			unsafe.Pointer(&keyBuf.Bytes()[0]),
			unsafe.Pointer(&buf.Bytes()[0]),
		)
		if err != nil {
			return fmt.Errorf("update unwind tables: %w", err)
		}
		shardIndex++
		buf.Reset()
		keyBuf.Reset()
	}

	// HACK(javierhonduco): remove this.
	// Debug stuff to compare this with the BPF program's view of the world.
	/* printRow := func(w io.Writer, pt unwind.UnwindTable, index int) {
		cfaInfo := ""
		switch ut[index].CFA.Rule {
		case frame.RuleCFA:
			cfaInfo = fmt.Sprintf("CFA Reg: %d Offset:%d", ut[index].CFA.Reg, ut[index].CFA.Offset)
		case frame.RuleExpression:
			cfaInfo = "CFA exp"
		default:
			panic("CFA rule is not valid. This should never happen.")
		}

		fmt.Fprintf(w, "\trow[%d]. Loc: %x, %s, $rbp: %d\n", index, pt[index].Loc, cfaInfo, pt[index].RBP.Offset)
	}

	fmt.Fprintf(os.Stdout, "\t- Total entries %d\n\n", len(ut))
	printRow(os.Stdout, ut, 0)
	printRow(os.Stdout, ut, 1)
	printRow(os.Stdout, ut, 2)
	printRow(os.Stdout, ut, 6)
	printRow(os.Stdout, ut, len(ut)-1) */

	return nil
}
