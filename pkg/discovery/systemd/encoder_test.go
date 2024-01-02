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
	"testing"
)

func TestEscapeBusLabel(t *testing.T) {
	tt := map[string]string{
		"":                                     "_",
		"dbus":                                 "dbus",
		"dbus.service":                         "dbus_2eservice",
		"foo@bar.service":                      "foo_40bar_2eservice",
		"foo_bar@bar.service":                  "foo_5fbar_40bar_2eservice",
		"systemd-networkd-wait-online.service": "systemd_2dnetworkd_2dwait_2donline_2eservice",
		"555":                                  "_3555",
		"dev-ttyS8.device":                     "dev_2dttyS8_2edevice",
	}

	buf := &bytes.Buffer{}

	for name, want := range tt {
		buf.Reset()

		escapeBusLabel(name, buf)
		got := buf.String()
		if want != got {
			t.Errorf("expected %q got %q", want, got)
		}
	}
}

func BenchmarkEscapeBusLabel(b *testing.B) {
	buf := &bytes.Buffer{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()

		escapeBusLabel("dbus.service", buf)
		got = buf.Bytes()
	}
}
