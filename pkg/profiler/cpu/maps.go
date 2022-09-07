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
	"io"
	"os"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

const (
	countsMapName      = "stack_counts"
	stackTracesMapName = "stack_traces"
	unwindTableMapName = "unwind_tables"

	maxPlanTableSize = 130 * 1000 // // Always needs to be sync with MAX_UNWIND_TABLE_SIZE in BPF program.
)

var (
	errMissing       = errors.New("missing stack trace")
	errUnwindFailed  = errors.New("stack ID is 0, probably stack unwinding failed")
	errUnrecoverable = errors.New("unrecoverable error")
)

type bpfMaps struct {
	byteOrder binary.ByteOrder

	stackCounts  *bpf.BPFMap
	stackTraces  *bpf.BPFMap
	unwindTables *bpf.BPFMap
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

// updateUnwindTables updates the unwind tables with the given plan table.
func (m *bpfMaps) updateUnwindTables(pid int, pt unwind.PlanTable, mainLowPC uint64, mainHighPC uint64) error {
	// Ignore RIP right now, it's usually 8 bytes before the CFA.

	buf := new(bytes.Buffer)

	// Write `main_low_pc`.
	if err := binary.Write(buf, m.byteOrder, mainLowPC); err != nil {
		return fmt.Errorf("write mainLowPC bytes: %w", err)
	}

	// Write `main_high_pc`.
	if err := binary.Write(buf, m.byteOrder, mainHighPC); err != nil {
		return fmt.Errorf("write mainHighPC bytes: %w", err)
	}

	// Write number of rows `.table_len``.
	if err := binary.Write(buf, m.byteOrder, uint64(len(pt))); err != nil {
		return fmt.Errorf("write PC bytes: %w", err)
	}

	for i, row := range pt {
		if i >= maxPlanTableSize {
			panic(fmt.Sprintf("max plan table size reached. Table size %d, but max size is %d", len(pt), maxPlanTableSize))
			break
		}
		// Ignore RIP right now, it's usually 8 bytes before the CFA.
		/* 		ip, err := row.RA.Bytes(m.byteOrder)
		   		if err != nil {
		   			return fmt.Errorf("get RIP bytes: %w", err)
		   		}
		   		rip[i] = ip
		*/

		// Write PC.
		if err := binary.Write(buf, m.byteOrder, row.Loc); err != nil {
			return fmt.Errorf("write PC bytes: %w", err)
		}

		// Write CFA register.
		if err := binary.Write(buf, m.byteOrder, row.CFA.Reg); err != nil {
			return fmt.Errorf("write CFA Reg bytes: %w", err)
		}

		// Write CFA offset.
		if err := binary.Write(buf, m.byteOrder, row.CFA.Offset); err != nil {
			return fmt.Errorf("write CFA offset bytes: %w", err)
		}

		// Write $rbp offset.
		if err := binary.Write(buf, m.byteOrder, row.RBP.Offset); err != nil {
			return fmt.Errorf("write RBP offset bytes: %w", err)
		}
	}

	// Upload PID -> full table mapping.
	if err := m.unwindTables.Update(unsafe.Pointer(&pid), unsafe.Pointer(&buf.Bytes()[0])); err != nil {
		return fmt.Errorf("update unwind tables: %w", err)
	}

	// TODO(javierhonduco): remove this.
	// Debug stuff to compare this with the BPF program's view of the world.
	fmt.Println("=======================")
	fmt.Fprintf(os.Stdout, "\t- Total entries %d\n\n", len(pt))

	printRow := func(w io.Writer, pt unwind.PlanTable, index int) {
		fmt.Fprintf(w, "\trow[%d]. Loc: %x, CFA Reg: %d Offset:%d, $rbp: %d\n", index, pt[index].Loc, pt[index].CFA.Reg, pt[index].CFA.Offset, pt[index].RBP.Offset)
	}
	printRow(os.Stdout, pt, 0)
	printRow(os.Stdout, pt, 1)
	printRow(os.Stdout, pt, 2)
	printRow(os.Stdout, pt, len(pt)-1)

	return nil
}

// cleanup removes all the data from the bpf maps.
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
