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
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"testing"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	embed_test "github.com/parca-dev/parca-agent"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

// The intent of these tests is to ensure that BTF relocations behaves the
// way we expect.
//
// We also use them to ensure that different kernel versions load our
// BPF program.
func setUpBpfProgram(t *testing.T) (*bpf.Module, error) {
	t.Helper()

	bpfObj, err := embed_test.BPFBundle.ReadFile("dist/btf/test.bpf.o")
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

	cpus := runtime.NumCPU()
	for i := 0; i < cpus; i++ {
		fd, err := unix.PerfEventOpen(&unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: 100,
			Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		}, -1 /* pid */, i /* cpu id */, -1 /* group */, 0 /* flags */)
		require.NoError(t, err)

		prog, err := m.GetProgram("profile_cpu")
		require.NoError(t, err)

		_, err = prog.AttachPerfEvent(fd)
		require.NoError(t, err)
	}

	return m, nil
}

func TestDeleteNonExistentKeyReturnsEnoent(t *testing.T) {
	m, err := setUpBpfProgram(t)
	require.NoError(t, err)
	t.Cleanup(m.Close)

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := m.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	require.NoError(t, err)

	pb.Start()
	numberOfEventsReceived := 0

	// go func() {
	// 	for {
	// 		syscall.Mmap(999, 999, 999, 1, 1)
	// 	}
	// }()

recvLoop:
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	pb.Stop()
	pb.Close()

	// pid := os.Getpid()

	// zero := uint32(0)
	// value, err := bpfMap.GetValue(unsafe.Pointer(&zero))
	// require.Error(t, err)

	// var btfPid int
	// err = binary.Read(bytes.NewBuffer(value), binary.LittleEndian, &btfPid)
	// require.NoError(t, err)

	// require.Equal(t, pid, btfPid)
}
