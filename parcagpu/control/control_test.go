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
	"bytes"
	"encoding/binary"
	"testing"
)

// The generated types must match parcagpu_ctl.h's layout.
func TestTypeSizes(t *testing.T) {
	for _, tc := range []struct {
		v    any
		size int
	}{{ctlConfig{}, 4 * 32}, {ctlDevice{}, 32}, {ctlState{}, 16 + 16*32 + 8}} {
		if got := binary.Size(tc.v); got != tc.size {
			t.Errorf("%T: %d bytes, want %d", tc.v, got, tc.size)
		}
	}
}

// A newer parcagpu's state may be longer; a shorter one isn't a state.
func TestDecodeState(t *testing.T) {
	want := ctlState{Pc_capable: 1, Rate_limit: 7, Num_devices: 1, Features: featureKernelStats}
	want.Devices[0].Pc_state = pcOn
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, want)
	full := b.Bytes()

	if got, err := decodeState(full); err != nil || got != want {
		t.Errorf("current: %+v, %v", got, err)
	}
	if got, err := decodeState(append(append([]byte{}, full...), 1, 2, 3, 4)); err != nil || got != want {
		t.Errorf("longer: %+v, %v", got, err)
	}
	if _, err := decodeState(full[:len(full)-1]); err == nil {
		t.Error("truncated state decoded")
	}
}
