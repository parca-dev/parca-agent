// Copyright 2026 The Parca Authors
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

// Package control drives PC sampling, and sets the launch probe rate limits,
// in parcagpu, the CUDA injection library, in every instrumented process on
// the node, over procctl
// (github.com/parca-dev/procctl). Each process reports the GPUs it uses and
// how it samples them (the schema is parcagpu_ctl.h, copied from parcagpu).
// CUPTI PC samples one process per GPU at a time, so the controller gives
// each GPU to one process at a time, in turns (scheduler), and keeps the
// profiler's per-process GPU configuration in step with what they report.
package control

//go:generate sh -c "go tool cgo -godefs types_def.go | gofmt > types_gen.go && rm -rf _obj"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"github.com/parca-dev/procctl"
	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
)

// consumer names parcagpu's procctl regions (PARCAGPU_CTL_CONSUMER).
const consumer = "parcagpu"

// tickInterval paces state reads and turns: a hand-over takes a tick or
// two.
const tickInterval = 250 * time.Millisecond

// Options configures the controller.
type Options struct {
	// Rescan is how often /proc is scanned for new processes; Notify finds
	// them sooner.
	Rescan time.Duration
	// Lease is how long processes keep the agent's configuration after it
	// stops heartbeating (it crashed, or was stopped without Close).
	Lease time.Duration
	// Settings are the initial settings, and those a settings file or
	// request falls back to where it sets nothing.
	Settings Settings
}

// Controller tracks parcagpu processes over procctl.
type Controller struct {
	reg   *procctl.Registry
	log   *slog.Logger
	sched *scheduler

	base       Settings
	settingsMu sync.Mutex
	settings   Settings
	setCh      chan Settings // to loop, which owns sched
	gauges     settingsGauges

	// Owned by loop.
	clients map[procctl.Key]*procctl.Client

	activeMu sync.Mutex
	active   map[int]time.Time // pid -> last kernel activity

	cancel context.CancelFunc
	done   chan struct{}
}

// Start begins controlling parcagpu processes. Close it on shutdown.
func Start(ctx context.Context, opts Options, metrics prometheus.Registerer) (*Controller, error) {
	if err := opts.Settings.Validate(); err != nil {
		return nil, err
	}
	log := slog.Default().With("component", "parcagpu-control")
	reg, err := procctl.NewRegistry(procctl.RegistryOptions{
		Consumer:       consumer,
		RescanInterval: opts.Rescan,
		Lease:          opts.Lease,
		Logger:         log,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &Controller{
		reg:      reg,
		log:      log,
		sched:    newScheduler(opts.Settings.schedConfig(), log, metrics),
		base:     opts.Settings,
		settings: opts.Settings,
		setCh:    make(chan Settings, 1),
		gauges:   newSettingsGauges(metrics),
		clients:  map[procctl.Key]*procctl.Client{},
		active:   map[int]time.Time{},
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	c.gauges.set(opts.Settings)
	go func() { _ = reg.Run(ctx) }()
	go c.loop(ctx)
	return c, nil
}

// GPUProcess reports a process that has set up a GPU (it may have just
// loaded parcagpu), so that it is found before the next rescan.
func (c *Controller) GPUProcess(pid int) { c.reg.Notify(pid) }

// KernelActivity reports that the profiler saw pid run kernels. Only such
// processes take turns at PC sampling.
func (c *Controller) KernelActivity(pid int) {
	now := time.Now()
	c.activeMu.Lock()
	c.active[pid] = now
	c.activeMu.Unlock()
}

func (c *Controller) lastActive(pid int) time.Time {
	c.activeMu.Lock()
	defer c.activeMu.Unlock()
	return c.active[pid]
}

// Close stops the controller and releases the processes: a successor agent
// takes them over without their configuration lapsing.
func (c *Controller) Close() error {
	c.cancel()
	<-c.done
	return c.reg.Close()
}

func (c *Controller) loop(ctx context.Context) {
	defer close(c.done)
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-c.reg.Events():
			info := ev.Client.Info()
			switch ev.Kind {
			case procctl.Attached:
				c.clients[info.Key] = ev.Client
			case procctl.Detached:
				delete(c.clients, info.Key)
				c.sched.remove(info.HostPID)
				c.activeMu.Lock()
				delete(c.active, info.HostPID)
				c.activeMu.Unlock()
			}
		case s := <-c.setCh:
			c.sched.cfg = s.schedConfig()
			c.gauges.set(s)
			c.log.Info("GPU control settings changed", "settings", s.String())
		case now := <-tick.C:
			c.readAll(ctx)
			c.sched.tick(now)
		}
	}
}

func (c *Controller) readAll(ctx context.Context) {
	for _, cl := range c.clients {
		pid := cl.Info().HostPID
		st, applied, err := readState(ctx, cl)
		if err != nil {
			c.log.Debug("reading state", "pid", pid, "err", err)
			continue
		}
		c.sched.update(pid, cl, st, applied, c.lastActive(pid))
		storeGpuConfig(uint32(pid), &st)
	}
}

// readState reads and decodes a process's state, and the latest generation
// it acknowledged.
func readState(ctx context.Context, c *procctl.Client) (ctlState, uint64, error) {
	var s ctlState
	st, err := c.ReadState(ctx)
	if err != nil {
		return s, 0, err
	}
	if st.Stale || len(st.Consumer) < int(unsafe.Sizeof(s)) {
		return s, 0, errNoState
	}
	err = binary.Read(bytes.NewReader(st.Consumer), binary.LittleEndian, &s)
	if s.Num_devices > maxDevices {
		s.Num_devices = maxDevices
	}
	return s, st.AppliedGen, err
}

var errNoState = errors.New("no parcagpu state")

// storeGpuConfig keeps the profiler's per-process GPU configuration, which
// turns PC sample counts into time, in step with the sampling factor the
// process reports: the factor can change while the process runs, and the
// gpu_config probe reports a device only once. The cache holds one
// configuration per process: the device sampling now if any, else the first.
func storeGpuConfig(pid uint32, s *ctlState) {
	var d *ctlDevice
	for i := range s.Devices[:s.Num_devices] {
		dev := &s.Devices[i]
		if dev.Sampling_factor == 0 || dev.Clock_khz == 0 {
			continue
		}
		if d == nil || dev.Pc_state == pcOn {
			d = dev
		}
		if dev.Pc_state == pcOn {
			break
		}
	}
	if d == nil {
		return
	}
	cfg := &gpu.GpuConfig{SamplingFactor: d.Sampling_factor, ClockKHz: d.Clock_khz, SMCount: d.Sm_count}
	if prev, ok := gpu.LoadGpuConfig(pid); ok {
		if prev.SamplingFactor == cfg.SamplingFactor && prev.ClockKHz == cfg.ClockKHz &&
			prev.SMCount == cfg.SMCount {
			return
		}
		cfg.DeviceID = prev.DeviceID
	}
	gpu.StoreGpuConfig(pid, cfg)
}
