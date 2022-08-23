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

package discovery

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseUnitList(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty",
			args: args{in: ""},
			want: []string{},
		},
		{
			name: "real",
			args: args{
				in: `  UNIT                             LOAD   ACTIVE SUB     DESCRIPTION                               >
  atop.service                     loaded active running Atop advanced performance monitor
  avahi-daemon.service             loaded active running Avahi mDNS/DNS-SD Stack
  bluetooth.service                loaded active running Bluetooth service
  cups.service                     loaded active running CUPS Scheduler
  dbus.service                     loaded active running D-Bus System Message Bus
  docker.service                   loaded active running Docker Application Container Engine
  getty@tty1.service               loaded active running Getty on tty1
  grafana.service                  loaded active running Grafana service
  ly.service                       loaded active running TUI display manager
  NetworkManager.service           loaded active running Network Manager
  nordvpnd.service                 loaded active running NordVPN Daemon
  polkit.service                   loaded active running Authorization Manager
  prometheus-node-exporter.service loaded active running Prometheus exporter for machine metrics
  rtkit-daemon.service             loaded active running RealtimeKit Scheduling Policy Service
  sshd.service                     loaded active running OpenSSH Daemon
  systemd-journald.service         loaded active running Journal Service
  systemd-logind.service           loaded active running User Login Management
  systemd-machined.service         loaded active running Virtual Machine and Container Registration>
  systemd-resolved.service         loaded active running Network Name Resolution
  systemd-timesyncd.service        loaded active running Network Time Synchronization
  systemd-udevd.service            loaded active running Rule-based Manager for Device Events and F>
  tailscaled.service               loaded active running Tailscale node agent
  udisks2.service                  loaded active running Disk Manager
  upower.service                   loaded active running Daemon for power management
  user@1000.service                loaded active running User Manager for UID 1000
  wpa_supplicant.service           loaded active running WPA supplicant

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
26 loaded units listed.
`,
			},
			want: []string{
				"atop.service",
				"avahi-daemon.service",
				"bluetooth.service",
				"cups.service",
				"dbus.service",
				"docker.service",
				"getty@tty1.service",
				"grafana.service",
				"ly.service",
				"NetworkManager.service",
				"nordvpnd.service",
				"polkit.service",
				"prometheus-node-exporter.service",
				"rtkit-daemon.service",
				"sshd.service",
				"systemd-journald.service",
				"systemd-logind.service",
				"systemd-machined.service",
				"systemd-resolved.service",
				"systemd-timesyncd.service",
				"systemd-udevd.service",
				"tailscaled.service",
				"udisks2.service",
				"upower.service",
				"user@1000.service",
				"wpa_supplicant.service",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, parseUnitList(bytes.NewBufferString(tt.args.in)))
		})
	}
}
