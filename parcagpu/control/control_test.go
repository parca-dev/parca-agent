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
