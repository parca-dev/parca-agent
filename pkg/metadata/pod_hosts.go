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

package metadata

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/prometheus/common/model"
)

var (
	initHostname    sync.Once
	hostname        string
	errInitHostname error
)

// PodHosts provide pod_ip and pod_hostname if pid is a pod.
func PodHosts() Provider {
	return &StatelessProvider{"hosts", func(ctx context.Context, pid int) (model.LabelSet, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		initHostname.Do(func() {
			local, err := getExternalIPAndHost(1)
			if err != nil {
				errInitHostname = err
				return
			}
			hostname = local.hostname
		})
		if errInitHostname != nil {
			return nil, errInitHostname
		}
		e, err := getExternalIPAndHost(pid)
		if err != nil {
			return nil, err
		}
		if hostname != e.hostname {
			// pod
			return model.LabelSet{
				"pod_ip":       model.LabelValue(e.ip),
				"pod_hostname": model.LabelValue(e.hostname),
			}, nil
		}
		return nil, nil
	}}
}

type hostEntry struct {
	ip       string
	hostname string
}

func getExternalIPAndHost(pid int) (hostEntry, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/etc/hosts", pid))
	if err != nil {
		return hostEntry{}, err
	}
	hostEntries, err := parseHosts(bytes.NewReader(data))
	if err != nil {
		return hostEntry{}, err
	}
	if len(hostEntries) == 0 {
		return hostEntry{}, fmt.Errorf("read hosts file result nil, raw:%s", string(data))
	}
	return hostEntries[len(hostEntries)-1], nil
}

func parseHosts(r io.Reader) ([]hostEntry, error) {
	var res []hostEntry
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := string(s.Bytes())
		fileds := strings.Fields(line)
		if len(fileds) < 2 || fileds[0] == "#" {
			continue
		}
		res = append(res, hostEntry{
			ip:       fileds[0],
			hostname: fileds[1],
		})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
