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

// TODO(javierhonduco): Rename this discovery mechanism to a Cgroups as it's
// a more suitable name.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/target"
)

type CgroupConfig struct {
	units      map[string]struct{}
	cgroupPath string
}

type CgroupDiscoverer struct {
	units         map[string]struct{}
	unitProfilers map[string]struct{}
	logger        log.Logger
	cgroupPath    string

	mtx sync.RWMutex
}

func (c *CgroupConfig) Name() string {
	return "cgroup"
}

func NewCgroupConfig(cgroupUnits []string, cgroupCgroupPath string) *CgroupConfig {
	units := map[string]struct{}{}

	for _, unit := range cgroupUnits {
		units[unit] = struct{}{}
	}
	return &CgroupConfig{
		units:      units,
		cgroupPath: cgroupCgroupPath,
	}
}

func (c *CgroupConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	return &CgroupDiscoverer{
		units:         c.units,
		cgroupPath:    c.cgroupPath,
		unitProfilers: make(map[string]struct{}),
		logger:        d.Logger,
	}, nil
}

func (c *CgroupDiscoverer) Run(ctx context.Context, up chan<- []*target.Group) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		level.Debug(c.logger).Log("msg", "running cgroup manager", "units", len(c.units))
		var targetGroups []*target.Group

		for unit := range c.units {
			labelset, err := c.ReconcileUnit(ctx, unit)
			if err != nil {
				return err
			}

			labelset["cgroup_path"] = model.LabelValue(unit)

			targetGroups = append(targetGroups, &target.Group{
				Targets: []model.LabelSet{labelset},
				Source:  unit,
			})
		}

		up <- targetGroups
	}
}

func (c *CgroupDiscoverer) ReconcileUnit(ctx context.Context, unit string) (model.LabelSet, error) {
	// If the user has specified a cgroup path prefer that as opposed to
	// trying to figure it out ourselves.
	if c.cgroupPath != "" {
		p := path.Join(c.cgroupPath, unit)
		return model.LabelSet{agent.CgroupPathLabelName: model.LabelValue(p)}, nil
	}
	// Note: It's ok to call cgroups.Mode() here instead of storing it somewhere because
	// internally it's memoized.
	if cgroups.Mode() == cgroups.Unified {
		// If we're running under cgroupv2 the perf_event controller is always implicitly enabled
		// so we don't have to do anything special here.
		p := fmt.Sprintf("/sys/fs/cgroup/system.slice/%s/", unit)
		return model.LabelSet{agent.CgroupPathLabelName: model.LabelValue(p)}, nil
	}

	f, err := os.Open(fmt.Sprintf("/sys/fs/cgroup/cgroup/system.slice/%s/cgroup.procs", unit))
	if os.IsNotExist(err) {
		c.mtx.Lock()

		delete(c.unitProfilers, unit)
		c.mtx.Unlock()
		// TODO(brancz): cleanup cgroup os.Remove(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/")
		return model.LabelSet{agent.CgroupPathLabelName: model.LabelValue(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit))}, nil
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
			agent.CgroupPathLabelName: model.LabelValue(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit)),
		}, nil
	}

	level.Debug(c.logger).Log("msg", "adding cgroup unit profiler")
	c.mtx.Lock()
	c.unitProfilers[unit] = struct{}{}
	c.mtx.Unlock()

	return model.LabelSet{agent.CgroupPathLabelName: model.LabelValue(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit))}, nil
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
