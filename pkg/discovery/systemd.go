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
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"
)

type SystemdConfig struct{}

type SystemdDiscoverer struct {
	logger        log.Logger
	oldSourceList map[string]struct{}
}

func (c *SystemdConfig) Name() string {
	return "systemd"
}

func NewSystemdConfig() *SystemdConfig {
	return &SystemdConfig{}
}

func (c *SystemdConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	return &SystemdDiscoverer{
		logger: d.Logger,
	}, nil
}

func (c *SystemdDiscoverer) Run(ctx context.Context, up chan<- []*Group) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		units, err := c.units(ctx)
		if err != nil {
			return fmt.Errorf("failed to list units: %w", err)
		}
		newSourceList := map[string]struct{}{}
		var targetGroups []*Group
		for _, unit := range units {
			labelset := model.LabelSet{
				"systemd_unit": model.LabelValue(unit),
			}
			pids, err := c.pids(ctx, unit)
			if err != nil {
				level.Debug(c.logger).Log("msg", "failed to get PIDs for unit", "unit", unit, "err", err)
				continue
			}

			newSourceList[unit] = struct{}{}

			targetGroups = append(targetGroups, &Group{
				Targets: []model.LabelSet{{}},
				Labels:  labelset,
				Source:  unit,
				PIDs:    pids,
			})
		}

		// Add empty groups for targets which have been removed since the previous run.
		for unit := range c.oldSourceList {
			if _, ok := newSourceList[unit]; !ok {
				targetGroups = append(targetGroups, &Group{Source: unit})
			}
		}
		c.oldSourceList = newSourceList

		up <- targetGroups
	}
}

func (c *SystemdDiscoverer) units(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--state=running")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	units := parseUnitList(stdout)
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return units, nil
}

func parseUnitList(stdout io.Reader) []string {
	units := []string{}
	s := bufio.NewScanner(stdout)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "UNIT") ||
			strings.HasPrefix(line, "LOAD") ||
			strings.HasPrefix(line, "ACTIVE") ||
			strings.HasPrefix(line, "SUB") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		units = append(units, fields[0])
	}
	if len(units) > 0 {
		units = units[:len(units)-1]
	}
	return units
}

func (c *SystemdDiscoverer) pids(ctx context.Context, unit string) ([]int, error) {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "show", "--property", "MainPID", "--value", unit)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return nil, err
	}

	return []int{pid}, nil
}
