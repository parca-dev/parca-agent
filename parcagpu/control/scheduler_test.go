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

package control

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeProc is a parcagpu process: it applies (and acks) each configuration
// as it is written, unless stuck, and reports pc_state ON where granted.
type fakeProc struct {
	pid     int
	gpus    []string // device UUIDs, by slot
	capable bool
	stuck   bool
	idle    bool // runs no kernels

	gen, applied uint64
	cfg          ctlConfig
	writes       int
}

func (f *fakeProc) Write(b []byte) (uint64, error) {
	f.gen += 2
	f.writes++
	if !f.stuck {
		_ = binary.Read(bytes.NewReader(b), binary.LittleEndian, &f.cfg)
		f.applied = f.gen
	}
	return f.gen, nil
}

func (f *fakeProc) state() ctlState {
	s := ctlState{Num_devices: uint32(len(f.gpus))}
	if f.capable {
		s.Pc_capable = 1
	}
	for i, g := range f.gpus {
		copy(s.Devices[i].Uuid[:], g)
		if f.cfg.Sampling_devices&(1<<i) != 0 {
			s.Devices[i].Pc_state = pcOn
		}
	}
	return s
}

// on reports whether f samples gpu.
func (f *fakeProc) on(gpu string) bool {
	for i, g := range f.gpus {
		if g == gpu && f.cfg.Sampling_devices&(1<<i) != 0 {
			return true
		}
	}
	return false
}

type harness struct {
	t     *testing.T
	s     *scheduler
	procs []*fakeProc
	now   time.Time
}

func newHarness(t *testing.T, scope string, procs ...*fakeProc) *harness {
	cfg := schedConfig{factor: 12, windowMs: 40, gapMs: 360, turn: 10 * time.Second, scope: scope}
	return &harness{
		t:     t,
		s:     newScheduler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		procs: procs,
		now:   time.Unix(1000, 0),
	}
}

func proc(pid int, gpus ...string) *fakeProc {
	return &fakeProc{pid: pid, gpus: gpus, capable: true}
}

// step advances the clock by d and runs one scheduler tick, then checks that
// no two processes sample one GPU (or, with ScopeNode, at all).
func (h *harness) step(d time.Duration) {
	h.t.Helper()
	h.now = h.now.Add(d)
	for _, f := range h.procs {
		var active time.Time
		if !f.idle {
			active = h.now
		}
		h.s.update(f.pid, f, f.state(), f.applied, active)
	}
	h.s.tick(h.now)
	on := map[string]int{}
	for _, f := range h.procs {
		for _, g := range f.gpus {
			if !f.on(g) {
				continue
			}
			key := g
			if h.s.cfg.scope == ScopeNode {
				key = "node"
			}
			if other, ok := on[key]; ok && other != f.pid {
				h.t.Fatalf("at %v: pids %d and %d both sample %s", h.now, other, f.pid, key)
			}
			on[key] = f.pid
		}
	}
}

// sampler returns the pid sampling gpu, or 0.
func (h *harness) sampler(gpu string) int {
	for _, f := range h.procs {
		if f.on(gpu) {
			return f.pid
		}
	}
	return 0
}

func (h *harness) remove(f *fakeProc) {
	for i, p := range h.procs {
		if p == f {
			h.procs = append(h.procs[:i], h.procs[i+1:]...)
		}
	}
	h.s.remove(f.pid)
}

func TestRotation(t *testing.T) {
	h := newHarness(t, ScopeGPU, proc(30, "A"), proc(10, "A"), proc(20, "A"))
	var holders []int
	for i := 0; i < 70*4; i++ {
		h.step(250 * time.Millisecond)
		if p := h.sampler("A"); p != 0 && (len(holders) == 0 || holders[len(holders)-1] != p) {
			holders = append(holders, p)
		}
	}
	want := []int{10, 20, 30, 10, 20, 30, 10}
	if !slices.Equal(holders, want) {
		t.Errorf("holders %v, want %v", holders, want)
	}
	if got := testutil.ToFloat64(h.s.rotations); got != 6 {
		t.Errorf("rotations %v", got)
	}
	for _, f := range h.procs {
		if f.cfg.Sampling_factor != 12 || f.cfg.Sampling_window_ms != 40 || f.cfg.Sampling_gap_ms != 360 {
			t.Errorf("pid %d: %+v", f.pid, f.cfg)
		}
	}
}

// Each GPU has its own turn; a multi-GPU process can hold several.
func TestPerGPU(t *testing.T) {
	both := proc(30, "A", "B")
	h := newHarness(t, ScopeGPU, proc(10, "A"), proc(20, "B"), both)
	concurrent := false
	for i := 0; i < 60*4; i++ {
		h.step(250 * time.Millisecond)
		a, b := h.sampler("A"), h.sampler("B")
		concurrent = concurrent || (a != 0 && b != 0 && a != b)
	}
	if !concurrent {
		t.Error("GPUs A and B never sampled by different processes at once")
	}
}

// With ScopeNode, one process samples at a time on the whole node.
func TestScopeNode(t *testing.T) {
	h := newHarness(t, ScopeNode, proc(10, "A"), proc(20, "B"), proc(30, "A", "B"))
	seen := map[int]bool{}
	for i := 0; i < 60*4; i++ {
		h.step(250 * time.Millisecond)
		for _, g := range []string{"A", "B"} {
			if p := h.sampler(g); p != 0 {
				seen[p] = true
			}
		}
	}
	if len(seen) != 3 {
		t.Errorf("holders %v, want all three", seen)
	}
	if f := h.procs[2]; !(f.cfg.Sampling_devices == 3 || f.cfg.Sampling_devices == 0) {
		t.Errorf("node scope grants a process all its devices: %b", f.cfg.Sampling_devices)
	}
}

// A holder that exits hands its turn on at once.
func TestHolderExits(t *testing.T) {
	a, b := proc(10, "A"), proc(20, "A")
	h := newHarness(t, ScopeGPU, a, b)
	h.step(time.Second)
	h.step(time.Second)
	if h.sampler("A") != 10 {
		t.Fatalf("holder %d", h.sampler("A"))
	}
	h.remove(a)
	h.step(250 * time.Millisecond)
	if h.sampler("A") != 20 {
		t.Errorf("after exit: holder %d", h.sampler("A"))
	}
}

// A holder that doesn't confirm it stopped keeps its turn; nobody else
// samples meanwhile.
func TestHandoverTimeout(t *testing.T) {
	a, b := proc(10, "A"), proc(20, "A")
	h := newHarness(t, ScopeGPU, a, b)
	h.step(time.Second)
	a.stuck = true
	for i := 0; i < 20*4; i++ {
		h.step(250 * time.Millisecond)
		if b.on("A") {
			t.Fatal("granted while the holder is still sampling")
		}
	}
	if got := testutil.ToFloat64(h.s.timeouts); got < 1 {
		t.Errorf("timeouts %v", got)
	}
	a.stuck = false
	for i := 0; i < 20*4 && !b.on("A"); i++ {
		h.step(250 * time.Millisecond)
	}
	if !b.on("A") {
		t.Error("never handed over after the holder recovered")
	}
}

// A lone process keeps its GPU: no needless stop and start.
func TestSingleCandidate(t *testing.T) {
	a := proc(10, "A")
	h := newHarness(t, ScopeGPU, a, &fakeProc{pid: 20, gpus: []string{"A"}}) // 20 can't PC sample
	for i := 0; i < 60; i++ {
		h.step(time.Second)
	}
	if !a.on("A") || a.writes != 1 {
		t.Errorf("on %v after %d writes", a.on("A"), a.writes)
	}
	if f := h.procs[1]; f.writes != 1 || f.cfg.Sampling_devices != 0 {
		t.Errorf("incapable process: %d writes, %+v", f.writes, f.cfg)
	}
}

// A process already sampling when the agent starts (a previous agent's
// holder) keeps its turn; nobody else is granted on top of it.
func TestAdoptsCurrentHolder(t *testing.T) {
	a, b := proc(10, "A"), proc(20, "A")
	b.cfg.Sampling_devices = 1 // granted by a previous agent
	h := newHarness(t, ScopeGPU, a, b)
	h.step(250 * time.Millisecond)
	if h.sampler("A") != 20 {
		t.Errorf("holder %d, want the one already sampling", h.sampler("A"))
	}
}

// A process that set up the GPU but runs no kernels (an inference server's
// front end) never gets it; the one doing the work always does.
func TestIdleNeverGranted(t *testing.T) {
	front, worker := proc(10, "A"), proc(20, "A")
	front.idle = true
	h := newHarness(t, ScopeGPU, front, worker)
	for i := 0; i < 40*4; i++ {
		h.step(250 * time.Millisecond)
		if front.on("A") {
			t.Fatal("idle process granted")
		}
	}
	if !worker.on("A") || testutil.ToFloat64(h.s.rotations) != 0 {
		t.Errorf("worker on %v, rotations %v", worker.on("A"), testutil.ToFloat64(h.s.rotations))
	}
}

// A holder that goes idle gives the GPU back: to the next active process,
// or to nobody.
func TestHolderGoesIdle(t *testing.T) {
	a, b := proc(10, "A"), proc(20, "A")
	h := newHarness(t, ScopeGPU, a, b)
	h.step(time.Second)
	if !a.on("A") {
		t.Fatal("a not holding")
	}
	a.idle = true
	for i := 0; i < 15*4 && !b.on("A"); i++ {
		h.step(250 * time.Millisecond)
	}
	if !b.on("A") || a.on("A") {
		t.Fatalf("after a went idle: a %v b %v", a.on("A"), b.on("A"))
	}
	b.idle = true
	for i := 0; i < 15*4 && b.on("A"); i++ {
		h.step(250 * time.Millisecond)
	}
	if a.on("A") || b.on("A") {
		t.Errorf("all idle: a %v b %v", a.on("A"), b.on("A"))
	}
}

// An idle process still sampling (a previous agent's grant) holds up any
// grant until it has stopped.
func TestWaitsForIdleSampler(t *testing.T) {
	old, worker := proc(10, "A"), proc(20, "A")
	old.idle, old.stuck = true, true
	old.cfg.Sampling_devices = 1 // granted by a previous agent, not letting go yet
	h := newHarness(t, ScopeGPU, old, worker)
	for i := 0; i < 8; i++ {
		h.step(250 * time.Millisecond) // step's invariant check fails on a double grant
	}
	if worker.on("A") {
		t.Fatal("granted while another process samples")
	}
	old.stuck = false
	old.cfg.Sampling_devices = 0
	h.step(250 * time.Millisecond)
	h.step(250 * time.Millisecond)
	if !worker.on("A") {
		t.Error("not granted after the old sampler stopped")
	}
}
