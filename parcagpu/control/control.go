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

// Package control talks to parcagpu, the CUDA injection library, in every
// instrumented process on the node, over procctl
// (github.com/parca-dev/procctl). Each process reports the GPUs it uses and
// how it samples them (the schema is parcagpu_ctl.h, copied from parcagpu).
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
)

// consumer names parcagpu's procctl regions (PARCAGPU_CTL_CONSUMER).
const consumer = "parcagpu"

const readInterval = time.Second

// Options configures the controller.
type Options struct {
	// Rescan is how often /proc is scanned for new processes; Notify finds
	// them sooner.
	Rescan time.Duration
	// Lease is how long processes keep the agent's configuration after it
	// stops heartbeating (it crashed, or was stopped without Close).
	Lease time.Duration
}

// Controller tracks parcagpu processes over procctl.
type Controller struct {
	reg *procctl.Registry
	log *slog.Logger

	mu      sync.Mutex
	clients map[procctl.Key]*process

	cancel context.CancelFunc
	done   chan struct{}
}

// process is one parcagpu process and what it last reported.
type process struct {
	c     *procctl.Client
	state ctlState
	valid bool
}

// Start begins discovering parcagpu processes. Close it on shutdown.
func Start(ctx context.Context, opts Options) (*Controller, error) {
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
		reg:     reg,
		log:     log,
		clients: map[procctl.Key]*process{},
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go func() { _ = reg.Run(ctx) }()
	go c.loop(ctx)
	return c, nil
}

// Notify reports a process that may have just loaded parcagpu, so that it is
// found before the next rescan.
func (c *Controller) Notify(pid int) { c.reg.Notify(pid) }

// Close stops the controller and releases the processes: a successor agent
// takes them over without their configuration lapsing.
func (c *Controller) Close() error {
	c.cancel()
	<-c.done
	return c.reg.Close()
}

func (c *Controller) loop(ctx context.Context) {
	defer close(c.done)
	tick := time.NewTicker(readInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-c.reg.Events():
			c.event(ev)
		case <-tick.C:
			c.readAll(ctx)
		}
	}
}

func (c *Controller) event(ev procctl.Event) {
	key := ev.Client.Info().Key
	c.mu.Lock()
	defer c.mu.Unlock()
	switch ev.Kind {
	case procctl.Attached:
		c.clients[key] = &process{c: ev.Client}
	case procctl.Detached:
		delete(c.clients, key)
	}
}

func (c *Controller) snapshot() []*process {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*process, 0, len(c.clients))
	for _, p := range c.clients {
		out = append(out, p)
	}
	return out
}

func (c *Controller) readAll(ctx context.Context) {
	for _, p := range c.snapshot() {
		st, err := readState(ctx, p.c)
		if err != nil {
			c.log.Debug("reading state", "pid", p.c.Info().HostPID, "err", err)
			continue
		}
		p.state, p.valid = st, true
	}
}

// readState reads and decodes a process's state.
func readState(ctx context.Context, c *procctl.Client) (ctlState, error) {
	var s ctlState
	st, err := c.ReadState(ctx)
	if err != nil {
		return s, err
	}
	if st.Stale || len(st.Consumer) < int(unsafe.Sizeof(s)) {
		return s, errNoState
	}
	err = binary.Read(bytes.NewReader(st.Consumer), binary.LittleEndian, &s)
	if s.Num_devices > maxDevices {
		s.Num_devices = maxDevices
	}
	return s, err
}

var errNoState = errors.New("no parcagpu state")
