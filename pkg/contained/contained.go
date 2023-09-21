// Copyright 2023 The Parca Authors
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

package contained

import (
	"embed"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"

	"go.uber.org/atomic"

	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

//go:embed bpf/*
var bpfObjects embed.FS

const (
	maxEvents      = 25
	pollIntervalMs = 50
	binaryPath     = "/proc/self/exe"
	symbolName     = "github.com/parca-dev/parca-agent/pkg/contained.testFunction"
)

//go:noinline
func testFunction() {
	fmt.Fprintf(io.Discard, "Side-effect to avoid the compiler to optimize it out.")
}

func IsRootPIDNamespace() (bool, error) {
	f, err := bpfObjects.Open(fmt.Sprintf("bpf/%s/pid_namespace.bpf.o", runtime.GOARCH))
	if err != nil {
		return false, fmt.Errorf("failed to open BPF object: %w", err)
	}
	defer f.Close()

	bpfObj, err := io.ReadAll(f)
	if err != nil {
		return false, fmt.Errorf("failed to read BPF object: %w", err)
	}

	bpfModule, err := libbpf.NewModuleFromBufferArgs(libbpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "pid-namespace",
	})
	if err != nil {
		return false, fmt.Errorf("new bpf module: %w", err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		return false, fmt.Errorf("new bpf module: %w", err)
	}

	prog, err := bpfModule.GetProgram("uprobe__test_function")
	if err != nil {
		return false, fmt.Errorf("failed to get program: %w", err)
	}

	offset, err := helpers.SymbolToOffset(binaryPath, symbolName)
	if err != nil {
		return false, fmt.Errorf("failed to compute function offset: %w", err)
	}

	_, err = prog.AttachUprobe(-1, binaryPath, offset)
	if err != nil {
		return false, fmt.Errorf("failed to attach uprobe: %w", err)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)

	perfBuf, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 64)
	if err != nil {
		return false, fmt.Errorf("failed to init perf buffer: %w", err)
	}
	defer perfBuf.Stop()
	defer perfBuf.Close()

	perfBuf.Poll(int(pollIntervalMs))

	var shouldRun atomic.Bool
	shouldRun.Store(true)
	defer func() {
		shouldRun.Store(false)
	}()

	go func() {
		for {
			if !shouldRun.Load() {
				break
			}
			testFunction()
		}
	}()

	for i := 0; i < maxEvents; i++ {
		b := <-eventsChannel
		val := int(binary.LittleEndian.Uint32(b))

		if val == os.Getpid() {
			return true, nil
		}
	}

	return false, nil
}
