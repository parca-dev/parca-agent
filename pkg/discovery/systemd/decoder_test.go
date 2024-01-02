// Copyright 2023-2024 The Parca Authors
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

package systemd

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecodeString(t *testing.T) {
	d := newDecoder(bytes.NewReader(testString))
	got, err := d.String()
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(wantTestString, string(got)); diff != "" {
		t.Errorf(diff)
	}
}

var got []byte

func BenchmarkDecodeString(b *testing.B) {
	d := newDecoder(nil)
	body := bytes.NewReader(testString)
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body.Seek(0, io.SeekStart)
		d.Reset(body)
		if got, err = d.String(); err != nil {
			b.Error(err)
		}

		body.Seek(0, io.SeekStart)
		d.Reset(body)
		if got, err = d.String(); err != nil {
			b.Error(err)
		}
	}
}

var (
	wantTestString = "dev-disk-by\\x2dpath-pci\\x2d0000:00:14.0\\x2dscsi\\x2d0:0:0:0.device"
	testString     = []byte{65, 0, 0, 0, 100, 101, 118, 45, 100, 105, 115, 107, 45, 98, 121, 92, 120, 50, 100, 112, 97, 116, 104, 45, 112, 99, 105, 92, 120, 50, 100, 48, 48, 48, 48, 58, 48, 48, 58, 49, 52, 46, 48, 92, 120, 50, 100, 115, 99, 115, 105, 92, 120, 50, 100, 48, 58, 48, 58, 48, 58, 48, 46, 100, 101, 118, 105, 99, 101, 0}
)
