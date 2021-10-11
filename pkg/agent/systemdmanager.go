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

package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
)

type SystemdManager struct {
	logger            log.Logger
	nodeName          string
	samplingRatio     float64
	externalLabels    map[string]string
	ksymCache         *ksym.KsymCache
	writeClient       profilestorepb.ProfileStoreServiceClient
	debugInfoClient   debuginfo.Client
	sink              func(Record)
	units             map[string]struct{}
	unitProfilers     map[string]*CgroupProfiler
	mtx               *sync.RWMutex
	tmpDir            string
	profilingDuration time.Duration
}

type SystemdUnitTarget struct {
	Name     string
	NodeName string
}

func (t *SystemdUnitTarget) Labels() []*profilestorepb.Label {
	return []*profilestorepb.Label{{
		Name:  "node",
		Value: t.NodeName,
	}, {
		Name:  "systemd_unit",
		Value: t.Name,
	}}
}

func (t *SystemdUnitTarget) PerfEventCgroupPath() string {
	return fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", t.Name)
}

func NewSystemdManager(
	logger log.Logger,
	nodeName string,
	units []string,
	samplingRatio float64,
	externalLabels map[string]string,
	ksymCache *ksym.KsymCache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	tmp string,
	profilingDuration time.Duration,
) *SystemdManager {
	unitsSet := map[string]struct{}{}

	for _, unit := range units {
		unitsSet[unit] = struct{}{}
	}

	g := &SystemdManager{
		logger:            logger,
		nodeName:          nodeName,
		samplingRatio:     samplingRatio,
		externalLabels:    externalLabels,
		ksymCache:         ksymCache,
		writeClient:       writeClient,
		debugInfoClient:   debugInfoClient,
		mtx:               &sync.RWMutex{},
		units:             unitsSet,
		unitProfilers:     map[string]*CgroupProfiler{},
		tmpDir:            tmp,
		profilingDuration: profilingDuration,
	}

	return g
}

func (m *SystemdManager) SetSink(sink func(Record)) {
	m.sink = sink
}

func (m *SystemdManager) ActiveProfilers() []Profiler {
	names := []string{}
	for unit := range m.units {
		names = append(names, unit)
	}
	sort.Strings(names)

	res := []Profiler{}
	for _, name := range names {
		res = append(res, m.unitProfilers[name])
	}

	return res
}

func (m *SystemdManager) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		level.Debug(m.logger).Log("msg", "running systemd manager", "units", len(m.units))
		for unit := range m.units {
			if err := m.reconcileUnit(ctx, unit); err != nil {
				return err
			}
		}
	}
}

func (m *SystemdManager) reconcileUnit(ctx context.Context, unit string) error {
	f, err := os.Open(fmt.Sprintf("/sys/fs/cgroup/systemd/system.slice/%s/cgroup.procs", unit))
	if os.IsNotExist(err) {
		m.mtx.Lock()
		p := m.unitProfilers[unit]
		if p != nil {
			p.Stop()
		}
		m.unitProfilers[unit] = nil
		m.mtx.Unlock()
		//TODO(brancz): cleanup cgroup os.Remove(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/")
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	err = os.MkdirAll(fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/", unit), os.ModePerm)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(f)
	for s.Scan() {
		if err := retryingWriteFile(
			fmt.Sprintf("/sys/fs/cgroup/perf_event/system.slice/%s/cgroup.procs", unit),
			[]byte(s.Text()),
			os.FileMode(0),
		); err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return err
	}

	m.mtx.RLock()
	_, exists := m.unitProfilers[unit]
	m.mtx.RUnlock()
	if exists {
		// profiler already running for this cgroup
		return nil
	}

	logger := log.With(m.logger, "systemdunit", unit)
	p := NewCgroupProfiler(
		logger,
		m.externalLabels,
		m.ksymCache,
		m.writeClient,
		m.debugInfoClient,
		&SystemdUnitTarget{
			Name:     unit,
			NodeName: m.nodeName,
		},
		m.profilingDuration,
		m.sink,
		m.tmpDir,
	)

	level.Debug(logger).Log("msg", "adding systemd unit profiler")
	m.mtx.Lock()
	m.unitProfilers[unit] = p
	m.mtx.Unlock()

	go func() {
		err := p.Run(ctx)
		if err != nil {
			level.Error(m.logger).Log("msg", "running systemd-unit profiler failed", "err", err)
		}
	}()

	return nil
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
