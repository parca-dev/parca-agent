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

package cpuinfo

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type InclusiveRange struct {
	First uint64
	Last  uint64
}

type CPUSet []InclusiveRange

func (s CPUSet) Num() uint64 {
	ret := uint64(0)
	for _, cpuRange := range s {
		ret += (cpuRange.Last - cpuRange.First + 1)
	}
	return ret
}

func OnlineCPUs() (CPUSet, error) {
	// The code here was inspired by
	// `readCPURange` and `parseCPURange`
	// from numcpus
	ret := make([]InclusiveRange, 0)
	buf, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	s := strings.Trim(string(buf), "\n ")
	for _, cpuRange := range strings.Split(s, ",") {
		if len(cpuRange) == 0 {
			continue
		}
		from, to, found := strings.Cut(cpuRange, "-")
		first, err := strconv.ParseUint(from, 10, 32)
		if err != nil {
			return nil, err
		}
		var last uint64
		if found {
			var err error
			last, err = strconv.ParseUint(to, 10, 32)
			if err != nil {
				return nil, err
			}
		} else {
			last = first
		}
		if last < first {
			return nil, fmt.Errorf("last online CPU in range (%d) less than first (%d)", last, first)
		}
		ret = append(ret, InclusiveRange{First: first, Last: last})
	}
	return ret, nil
}
