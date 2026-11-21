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

	"github.com/prometheus/client_golang/prometheus"
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
	id      Identity
	schema  uint32

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
		if f.cfg.Pc_sampling_devices&(1<<i) != 0 {
			s.Devices[i].Pc_state = pcOn
		}
	}
	return s
}

// on reports whether f samples gpu.
func (f *fakeProc) on(gpu string) bool {
	for i, g := range f.gpus {
		if g == gpu && f.cfg.Pc_sampling_devices&(1<<i) != 0 {
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
	cfg := schedConfig{
		procSettings: procSettings{factor: 12, windowMs: 40, gapMs: 360, rateLimit: 500, graphRateLimit: 50},
		turn:         10 * time.Second, scope: scope,
	}
	return &harness{
		t:     t,
		s:     newScheduler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
		procs: procs,
		now:   time.Unix(1000, 0),
	}
}

func proc(pid int, gpus ...string) *fakeProc {
	return &fakeProc{pid: pid, gpus: gpus, capable: true, schema: schemaVersion}
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
		h.s.update(f.pid, f, f.schema, f.state(), f.applied, active, f.id)
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
		if f.cfg.Pc_sampling_factor != 12 || f.cfg.Pc_sampling_window_ms != 40 || f.cfg.Pc_sampling_gap_ms != 360 ||
			f.cfg.Rate_limit != 500 || f.cfg.Graph_rate_limit != 50 {
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
	if f := h.procs[2]; !(f.cfg.Pc_sampling_devices == 3 || f.cfg.Pc_sampling_devices == 0) {
		t.Errorf("node scope grants a process all its devices: %b", f.cfg.Pc_sampling_devices)
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
	if f := h.procs[1]; f.writes != 1 || f.cfg.Pc_sampling_devices != 0 {
		t.Errorf("incapable process: %d writes, %+v", f.writes, f.cfg)
	}
}

// A process already sampling when the agent starts (a previous agent's
// holder) keeps its turn; nobody else is granted on top of it.
func TestAdoptsCurrentHolder(t *testing.T) {
	a, b := proc(10, "A"), proc(20, "A")
	b.cfg.Pc_sampling_devices = 1 // granted by a previous agent
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
	old.cfg.Pc_sampling_devices = 1 // granted by a previous agent, not letting go yet
	h := newHarness(t, ScopeGPU, old, worker)
	for i := 0; i < 8; i++ {
		h.step(250 * time.Millisecond) // step's invariant check fails on a double grant
	}
	if worker.on("A") {
		t.Fatal("granted while another process samples")
	}
	old.stuck = false
	old.cfg.Pc_sampling_devices = 0
	h.step(250 * time.Millisecond)
	h.step(250 * time.Millisecond)
	if !worker.on("A") {
		t.Error("not granted after the old sampler stopped")
	}
}

// Changed settings reach every process; with PC sampling off, holders give
// their GPUs back and nobody samples.
func TestSettingsChange(t *testing.T) {
	h := newHarness(t, ScopeGPU, proc(10, "A"), proc(20, "B"))
	for i := 0; i < 8; i++ {
		h.step(250 * time.Millisecond)
	}
	if h.sampler("A") != 10 || h.sampler("B") != 20 {
		t.Fatalf("samplers %d %d", h.sampler("A"), h.sampler("B"))
	}
	cfg := h.s.cfg
	cfg.gapMs, cfg.rateLimit, cfg.noPCSampling = 970, 7, true
	h.s.cfg = cfg
	for i := 0; i < 8; i++ {
		h.step(250 * time.Millisecond)
	}
	for _, f := range h.procs {
		if f.cfg.Pc_sampling_devices != 0 || f.cfg.Pc_sampling_gap_ms != 970 || f.cfg.Rate_limit != 7 {
			t.Errorf("pid %d: %+v", f.pid, f.cfg)
		}
	}
	if h.sampler("A") != 0 || h.sampler("B") != 0 {
		t.Fatalf("still sampling: %d %d", h.sampler("A"), h.sampler("B"))
	}
	cfg.noPCSampling = false
	h.s.cfg = cfg
	for i := 0; i < 8; i++ {
		h.step(250 * time.Millisecond)
	}
	if h.sampler("A") != 10 || h.sampler("B") != 20 {
		t.Fatalf("samplers after re-enabling %d %d", h.sampler("A"), h.sampler("B"))
	}
}

// Each process is told its workload's settings; one whose workload turns PC
// sampling off takes no turns, and the others share the GPU without it.
func TestWorkloadSettings(t *testing.T) {
	vllm, other, batch, mlVllm := proc(10, "A"), proc(20, "A"), proc(30, "A"), proc(40, "B")
	vllm.id = Identity{Name: "vllm"}
	batch.id = Identity{Name: "batch"}
	mlVllm.id = Identity{Name: "vllm", K8sNamespace: "ml"}
	h := newHarness(t, ScopeGPU, vllm, other, batch, mlVllm)
	reg := prometheus.NewRegistry()
	h.s = newScheduler(h.s.cfg, h.s.log, reg)
	f20, f22, rl := uint32(20), uint32(22), uint32(7)
	off := false
	h.s.cfg = Settings{
		PCSampling: true, Factor: 12, Window: 40 * time.Millisecond, Gap: 360 * time.Millisecond,
		Turn: time.Second, Scope: ScopeGPU, RateLimit: 500, GraphRateLimit: 50,
		Workloads: []WorkloadSettings{
			{Name: "vllm", Factor: &f20, RateLimit: &rl},
			{Name: "vllm", Namespace: "ml", Factor: &f22},
			{Name: "batch", PCSampling: &off},
			{Name: "typo"},
		},
	}.schedConfig()

	samplers := map[int]bool{}
	for i := 0; i < 40; i++ {
		h.step(250 * time.Millisecond)
		samplers[h.sampler("A")] = true
	}
	if !samplers[10] || !samplers[20] || samplers[30] {
		t.Errorf("GPU A samplers %v: want 10 and 20 to take turns, never 30", samplers)
	}
	for _, tc := range []struct {
		f              *fakeProc
		factor, rateLm uint32
	}{{vllm, 20, 7}, {other, 12, 500}, {batch, 12, 500}, {mlVllm, 22, 500}} {
		if tc.f.cfg.Pc_sampling_factor != tc.factor || tc.f.cfg.Rate_limit != tc.rateLm ||
			tc.f.cfg.Pc_sampling_window_ms != 40 {
			t.Errorf("pid %d told %+v", tc.f.pid, tc.f.cfg)
		}
	}
	if batch.cfg.Pc_sampling_devices != 0 {
		t.Errorf("batch granted %b", batch.cfg.Pc_sampling_devices)
	}

	count := func(label string) float64 {
		return testutil.ToFloat64(h.s.workloadProcs.WithLabelValues(label))
	}
	for label, want := range map[string]float64{"": 1, "vllm": 1, "ml/vllm": 1, "batch": 1, "typo": 0} {
		if got := count(label); got != want {
			t.Errorf("processes{workload=%q} = %v, want %v", label, got, want)
		}
	}

	// A process renamed (an SDK publishing its process context, say) moves to
	// its workload's settings at the next tick.
	other.id = Identity{Name: "batch"}
	h.step(250 * time.Millisecond)
	if other.cfg.Pc_sampling_devices != 0 {
		t.Errorf("renamed pid told %+v", other.cfg)
	}
	if count("batch") != 2 || count("") != 0 {
		t.Errorf("after rename: batch %v, global %v", count("batch"), count(""))
	}
	// Dropping a workload drops its series.
	cfg := h.s.cfg
	cfg.workloads = cfg.workloads[:3]
	h.s.cfg = cfg
	h.step(250 * time.Millisecond)
	if n := testutil.CollectAndCount(h.s.workloadProcs); n != 4 {
		t.Errorf("%d series after dropping typo, want 4", n)
	}
}

func TestWorkloadMatch(t *testing.T) {
	c := schedConfig{workloads: []workloadRule{
		{name: "a"}, {name: "a", namespace: "prod"}, {name: "b", namespace: "dev"},
	}}
	for _, tc := range []struct {
		id   Identity
		want int
	}{
		{Identity{}, -1},
		{Identity{Name: "a"}, 0},
		{Identity{Name: "a", K8sNamespace: "prod"}, 1},
		{Identity{Name: "a", ServiceNamespace: "prod"}, 1},
		{Identity{Name: "a", K8sNamespace: "dev"}, 0},
		{Identity{Name: "b"}, -1},
		{Identity{Name: "b", K8sNamespace: "dev"}, 2},
		{Identity{Name: "c"}, -1},
	} {
		if got := c.workload(tc.id); got != tc.want {
			t.Errorf("%+v: rule %d, want %d", tc.id, got, tc.want)
		}
	}
}

// Every process is told the features, and told again when they change.
func TestFeatures(t *testing.T) {
	a, b := proc(10, "A"), proc(20, "B")
	h := newHarness(t, ScopeGPU, a, b)
	h.s.cfg.features = featureKernelStats | featureBlockingCalls
	h.step(250 * time.Millisecond)
	for _, f := range h.procs {
		if f.cfg.Features != featureKernelStats|featureBlockingCalls || f.cfg.Rate_limit != 500 {
			t.Errorf("pid %d: %+v", f.pid, f.cfg)
		}
	}
	h.s.cfg.features = 0
	h.step(250 * time.Millisecond)
	if a.cfg.Features != 0 || b.cfg.Features != 0 {
		t.Errorf("features not cleared: %b, %b", a.cfg.Features, b.cfg.Features)
	}
}

// The schema version 3 knobs go only to processes that speak it; a version 2
// process gets the rest and keeps its environment's for those.
func TestV3KnobsBySchema(t *testing.T) {
	cur, v2 := proc(10, "A"), proc(20, "B")
	v2.schema = 2
	h := newHarness(t, ScopeGPU, cur, v2)
	h.s.cfg.pcHWBufferMB, h.s.cfg.metadataRefreshMs, h.s.cfg.blockingThresholdUs = 64, 5000, 50
	h.s.cfg.features = featureBlockingCalls
	h.step(250 * time.Millisecond)
	if c := cur.cfg; c.Pc_hw_buffer_mb != 64 || c.Metadata_refresh_ms != 5000 || c.Blocking_threshold_us != 50 {
		t.Errorf("schema 3: %+v", c)
	}
	if c := v2.cfg; c.Pc_hw_buffer_mb != 0 || c.Metadata_refresh_ms != 0 || c.Blocking_threshold_us != 0 ||
		c.Features != featureBlockingCalls || c.Rate_limit != 500 || !v2.on("B") {
		t.Errorf("schema 2: %+v", c)
	}
}
