// Copyright 2021 The Parca Authors
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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"
)

type SystemdConfig struct {
	units map[string]struct{}
}

type SystemdDiscoverer struct {
	units         map[string]struct{}
	unitProfilers map[string]struct{}
	logger        log.Logger

	mtx sync.RWMutex
}

func (c *SystemdConfig) Name() string {
	return "systemd"
}

func NewSystemdConfig(systemdUnits []string) *SystemdConfig {

	units := map[string]struct{}{}

	for _, unit := range systemdUnits {
		units[unit] = struct{}{}
	}
	return &SystemdConfig{
		units: units,
	}
}

func (c *SystemdConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	return &SystemdDiscoverer{
		units:         c.units,
		unitProfilers: make(map[string]struct{}),
		logger:        d.Logger,
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
		level.Debug(c.logger).Log("msg", "running systemd manager", "units", len(c.units))
		var targetGroups []*Group

		for unit := range c.units {

			labelset, err := c.ReconcileUnit(ctx, unit)
			if err != nil {
				return err
			}

			labelset["systemd_unit"] = model.LabelValue(unit)

			targetGroups = append(targetGroups, &Group{
				Targets: []model.LabelSet{labelset},
				Source:  unit,
			})
		}

		up <- targetGroups
	}
}

func (c *SystemdDiscoverer) ReconcileUnit(ctx context.Context, unit string) (model.LabelSet, error) {
	f, err := os.Open(fmt.Sprintf("/sys/fs/cgroup/systemd/system.slice/%s/cgroup.procs", unit))
	if os.IsNotExist(err) {
		c.mtx.Lock()

		delete(c.unitProfilers, unit)
		c.mtx.Unlock()
		//TODO(brancz): cleanup cgroup os.Remove(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/")
		return model.LabelSet{CgroupPathLabelName: model.LabelValue(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit))}, nil

	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	err = os.MkdirAll(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit), os.ModePerm)
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(f)
	for s.Scan() {
		if err := retryingWriteFile(
			fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/cgroup.procs", unit),
			[]byte(s.Text()),
			os.FileMode(0),
		); err != nil {
			return nil, err
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	c.mtx.RLock()
	_, exists := c.unitProfilers[unit]
	c.mtx.RUnlock()
	if exists {
		// profiler already running for this cgroup
		return model.LabelSet{
			CgroupPathLabelName: model.LabelValue(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit)),
		}, nil

	}

	level.Debug(c.logger).Log("msg", "adding systemd unit profiler")
	c.mtx.Lock()
	c.unitProfilers[unit] = struct{}{}
	c.mtx.Unlock()

	return model.LabelSet{CgroupPathLabelName: model.LabelValue(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit))}, nil
}

func retryingWriteFile(path string, data []byte, mode os.FileMode) error {
	// Retry writes on EINTR; see:
	//    https://github.com/golang/go/issues/38033
	for {
		err := ioutil.WriteFile(path, data, mode)
		if err == nil {
			return nil
		} else if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}
