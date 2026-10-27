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
	// Factor is the CUPTI sampling factor (period 2^Factor cycles), 5-31; 0
	// leaves it to each process.
	Factor uint32
	// Window is how long each PC sampling window stays open; 0 leaves it to
	// each process (30 ms).
	Window time.Duration
	// Gap is the pause between windows on a GPU: the duty cycle is
	// Window/(Window+Gap).
	Gap time.Duration
	// Turn is how long a process keeps a GPU while others wait for it.
	Turn time.Duration
	// Scope is ScopeGPU or ScopeNode.
	Scope string
	// RateLimit and GraphRateLimit are the launch probe rate limits, events
	// per second per thread, for kernel and CUDA graph launches; 0 leaves
	// them to each process (PARCAGPU_RATE_LIMIT, PARCAGPU_GRAPH_RATE_LIMIT).
	RateLimit      uint32
	GraphRateLimit uint32
}

// Controller tracks parcagpu processes over procctl.
type Controller struct {
	reg   *procctl.Registry
	log   *slog.Logger
	sched *scheduler

	// Owned by loop.
	clients map[procctl.Key]*procctl.Client

	activeMu sync.Mutex
	active   map[int]time.Time // pid -> last kernel activity

	cancel context.CancelFunc
	done   chan struct{}
}

// Start begins controlling parcagpu processes. Close it on shutdown.
func Start(ctx context.Context, opts Options, metrics prometheus.Registerer) (*Controller, error) {
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
		reg: reg,
		log: log,
		sched: newScheduler(schedConfig{
			factor:   opts.Factor,
			windowMs: uint32(opts.Window.Milliseconds()),
			gapMs:    uint32(opts.Gap.Milliseconds()),
			turn:     opts.Turn,
			scope:    opts.Scope,

			rateLimit:      opts.RateLimit,
			graphRateLimit: opts.GraphRateLimit,
		}, log, metrics),
		clients: map[procctl.Key]*procctl.Client{},
		active:  map[int]time.Time{},
		cancel:  cancel,
		done:    make(chan struct{}),
	}
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
