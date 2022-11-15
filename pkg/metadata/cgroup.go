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
//

package metadata

import (
	"fmt"
	"os"
	"strings"

	"github.com/prometheus/common/model"
)

func Cgroup() Provider {
	return &StatelessProvider{"cgroup", func(pid int) (model.LabelSet, error) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return nil, err
		}

		name, err := parseCgroupFileContents(string(data))
		if err != nil {
			return nil, err
		}
		return model.LabelSet{
			"cgroup_name": model.LabelValue(name),
		}, nil
	}}
}

func parseCgroupFileContents(data string) (string, error) {
	lines := strings.Split(data, "\n")
	line := ""
	// No newline or just a trailing one
	if len(lines) == 1 || len(lines) == 2 {
		line = lines[0]
	} else {
		foundCPUController := false
		for _, currentLine := range lines {
			if strings.Contains(currentLine, "cpu") && !strings.Contains(currentLine, "cpuset") {
				line = currentLine
				foundCPUController = true
				break
			}
		}

		if !foundCPUController {
			for _, currentLine := range lines {
				if strings.Contains(currentLine, "systemd") {
					line = currentLine
					break
				}
			}
		}
	}

	splittedCgroupPath := strings.Split(line, ":")
	if len(splittedCgroupPath) < 2 {
		return "", fmt.Errorf("cgroup data did not have the expected format, line: %s", line)
	}
	cgroupName := strings.TrimSpace(strings.Join(splittedCgroupPath[2:], ""))
	return cgroupName, nil
}
