// Copyright 2026 The Parca Authors
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

package control

import (
	"encoding/binary"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
)

// The generated types must match parcagpu_ctl.h's layout.
func TestTypeSizes(t *testing.T) {
	for _, tc := range []struct {
		v    any
		size int
	}{{ctlConfig{}, 24}, {ctlDevice{}, 32}, {ctlState{}, 16 + 16*32}} {
		if got := binary.Size(tc.v); got != tc.size {
			t.Errorf("%T: %d bytes, want %d", tc.v, got, tc.size)
		}
	}
}

func TestStoreGpuConfig(t *testing.T) {
	const pid = 4242
	s := ctlState{Num_devices: 3}
	s.Devices[0] = ctlDevice{Sampling_factor: 10, Clock_khz: 1000, Sm_count: 10}
	s.Devices[1] = ctlDevice{Sampling_factor: 12, Clock_khz: 2000, Sm_count: 20, Pc_state: pcOn}
	s.Devices[2] = ctlDevice{} // not configured
	storeGpuConfig(pid, &s)
	if got, _ := gpu.LoadGpuConfig(pid); got == nil || got.SamplingFactor != 12 || got.ClockKHz != 2000 {
		t.Fatalf("sampling device: got %+v", got)
	}

	gpu.StoreGpuConfig(pid, &gpu.GpuConfig{DeviceID: 7, SamplingFactor: 12, ClockKHz: 2000, SMCount: 20})
	s.Devices[1].Sampling_factor = 15 // changed live
	storeGpuConfig(pid, &s)
	if got, _ := gpu.LoadGpuConfig(pid); got.SamplingFactor != 15 || got.DeviceID != 7 {
		t.Fatalf("factor change: got %+v", got)
	}

	s.Devices[1].Pc_state = pcOff
	storeGpuConfig(pid, &s)
	if got, _ := gpu.LoadGpuConfig(pid); got.SamplingFactor != 10 {
		t.Fatalf("none sampling, first device: got %+v", got)
	}
}
