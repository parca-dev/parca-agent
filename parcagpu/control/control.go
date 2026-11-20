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
// each GPU to one process at a time, in turns (scheduler).
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
	"go.opentelemetry.io/otel/attribute"
)

// consumer names parcagpu's procctl regions (PARCAGPU_CTL_CONSUMER).
const consumer = "parcagpu"

// pruneInterval paces forgetting processes the profiler saw run kernels that
// procctl doesn't control.
const pruneInterval = time.Minute

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

	procs *procs

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
		procs:    newProcs(),
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
// processes take turns at PC sampling. res is the resource of the sample
// that showed it, empty if it has none: if it names the process differently
// than before, the process gets its new workload's settings.
func (c *Controller) KernelActivity(pid int, res attribute.Set) { c.procs.active(pid, res) }

// NameWith sets how processes are named for workload settings. Until it is
// called, and for a process the profiler hasn't resolved yet, processes get
// the global settings.
func (c *Controller) NameWith(n Namers) { c.procs.setNamers(n) }

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
	var lastPrune time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-c.reg.Events():
			info := ev.Client.Info()
			switch ev.Kind {
			case procctl.Attached:
				c.clients[info.Key] = ev.Client
				c.procs.attached(info.HostPID)
			case procctl.Detached:
				delete(c.clients, info.Key)
				c.sched.remove(info.HostPID)
				c.procs.forget(info.HostPID)
			}
		case s := <-c.setCh:
			c.sched.cfg = s.schedConfig()
			c.gauges.set(s)
			c.log.Info("GPU control settings changed", "settings", s.String())
		case now := <-tick.C:
			c.readAll(ctx)
			c.sched.tick(now)
			if now.Sub(lastPrune) >= pruneInterval {
				c.procs.prune(c.controlled, now, pruneInterval)
				lastPrune = now
			}
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
		lastActive, id := c.procs.lookup(pid)
		c.sched.update(pid, cl, st, applied, lastActive, id)
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

// controlled reports whether procctl controls pid. Only for loop.
func (c *Controller) controlled(pid int) bool {
	for _, cl := range c.clients {
		if cl.Info().HostPID == pid {
			return true
		}
	}
	return false
}
