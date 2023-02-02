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

package cpu

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var memlockRegex = regexp.MustCompile(`^memlock:\s+(\d+)$`)

func (c *bpfMetricsCollector) getBPFMetrics() []*bpfMetrics {
	var bpfMapsNames []string
	//nolint: prealloc
	var bpfMetricArray []*bpfMetrics

	it := c.m.Iterator()

	for {
		mapBpf := it.NextMap()
		if mapBpf != nil {
			bpfMapsNames = append(bpfMapsNames, mapBpf.Name())
		} else {
			break
		}
	}

	for _, mapName := range bpfMapsNames {
		bpfMap, err := c.m.GetMap(mapName)
		if err != nil {
			level.Debug(c.logger).Log("msg", "error fetching bpf map", "err", err)
			continue
		}

		bpfMaxEntry := float64(bpfMap.GetMaxEntries())
		bpfMapKeySize := float64(bpfMap.KeySize())
		bpfMapValueSize := float64(bpfMap.ValueSize())
		bpfMapFd := fmt.Sprint(bpfMap.FileDescriptor())

		path := fmt.Sprintf("/proc/%d/fdinfo/", c.pid) + bpfMapFd
		data, err := readFileNoStat(path)
		if err != nil {
			level.Debug(c.logger).Log("msg", "Unable to read fds for agent process", "agent_pid", c.pid, "err", err)
		}

		bpfMemlock, err := FdInfoMemlock(c.logger, data)
		if err != nil {
			level.Debug(c.logger).Log("msg", "error getting memory locked for file descriptor", "err", err)
		}

		bpfMetricArray = append(bpfMetricArray,
			&bpfMetrics{
				mapName:         mapName,
				bpfMapKeySize:   bpfMapKeySize,
				bpfMapValueSize: bpfMapValueSize,
				bpfMaxEntry:     bpfMaxEntry,
				bpfMemlock:      float64(bpfMemlock),
			},
		)
	}
	return bpfMetricArray
}

// FDInfoMemlock returns the memory locked by the fd for a process using fdinfo data.
func FdInfoMemlock(logger log.Logger, data []byte) (int, error) {
	var text, memlockValue string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		text = scanner.Text()
		if memlockRegex.MatchString(text) {
			memlockValue = memlockRegex.FindStringSubmatch(text)[1]
		}
	}

	memlockValueInt, err := strconv.Atoi(memlockValue)
	if err != nil {
		level.Debug(logger).Log("msg", "error converting memlock to integer type", "err", err)
	}
	return memlockValueInt, nil
}

func readFileNoStat(filename string) ([]byte, error) {
	const maxBufferSize = 1024 * 1024

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := io.LimitReader(f, maxBufferSize)
	return io.ReadAll(reader)
}
