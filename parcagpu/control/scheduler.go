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
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Scopes of a PC sampling holder: which processes share one turn.
const (
	// ScopeGPU: one process at a time per GPU; processes on different GPUs
	// sample at once.
	ScopeGPU = "gpu"
	// ScopeNode: one process at a time on the node.
	ScopeNode = "node"
)

// activityWindow: a process is a candidate for PC sampling only if the
// profiler saw it run kernels this recently. Processes that set up a GPU but
// don't use it (an inference server's front end, say) never take a turn.
const activityWindow = 10 * time.Second

// handoverTimeout bounds a hand-over: a holder that hasn't stopped sampling
// by then keeps its turn, and the next rotation tries again. parcagpu
// normally stops within ~100 ms, even while idle.
const handoverTimeout = 5 * time.Second

// schedConfig is what every process is told, and how turns rotate.
type schedConfig struct {
	factor   uint32 // parcagpu_ctl_config.pc_sampling_factor
	windowMs uint32
	gapMs    uint32
	turn     time.Duration
	scope    string

	rateLimit      uint32 // parcagpu_ctl_config.rate_limit
	graphRateLimit uint32

	noPCSampling bool // no process takes a turn
}

// target receives configuration; a *procctl.Client.
type target interface {
	Write(payload []byte) (uint64, error)
}

// schedProc is one process as the scheduler sees it.
type schedProc struct {
	pid        int
	t          target
	state      ctlState
	appliedGen uint64
	lastActive time.Time // last kernel activity the profiler saw
	written    []byte    // last payload written, nil before the first
	writtenGen uint64
}

// turnState is one holder key's turn: a GPU (by UUID) or, with ScopeNode,
// the node.
type turnState struct {
	pid        int // holder; 0 = none
	since      time.Time
	releasing  bool // the holder was told to stop, not yet confirmed
	releaseAt  time.Time
	releaseGen uint64 // the write that told it; 0 = not written yet
	last       int    // previous holder, for rotation order
}

// scheduler gives PC sampling to one process at a time per key, in turns.
// It is not safe for concurrent use.
type scheduler struct {
	cfg   schedConfig
	log   *slog.Logger
	procs map[int]*schedProc
	turns map[string]*turnState

	holderGauge *prometheus.GaugeVec
	rotations   prometheus.Counter
	timeouts    prometheus.Counter
}

func newScheduler(cfg schedConfig, log *slog.Logger, reg prometheus.Registerer) *scheduler {
	s := &scheduler{
		cfg:   cfg,
		log:   log,
		procs: map[int]*schedProc{},
		turns: map[string]*turnState{},
		holderGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "parca_agent_gpu_pc_sampling_holder",
			Help: "Host pid of the process allowed to PC sample, per GPU (or \"node\"); 0 when none.",
		}, []string{"gpu_uuid"}),
		rotations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_gpu_pc_sampling_rotations_total",
			Help: "PC sampling turns handed from one process to the next.",
		}),
		timeouts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_gpu_pc_sampling_handover_timeouts_total",
			Help: "Hand-overs abandoned because the holder didn't confirm it stopped sampling in time.",
		}),
	}
	if reg != nil {
		reg.MustRegister(s.holderGauge, s.rotations, s.timeouts)
	}
	return s
}

// update records a process's latest state, acknowledged generation, and last
// kernel activity.
func (s *scheduler) update(pid int, t target, st ctlState, appliedGen uint64, lastActive time.Time) {
	p := s.procs[pid]
	if p == nil {
		p = &schedProc{pid: pid, t: t}
		s.procs[pid] = p
	}
	p.state, p.appliedGen, p.lastActive = st, appliedGen, lastActive
}

// remove forgets an exited process.
func (s *scheduler) remove(pid int) { delete(s.procs, pid) }

// uuidKey formats a device UUID the way nvidia-smi does.
func uuidKey(u [16]uint8) string {
	return fmt.Sprintf("GPU-%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// slots returns p's device slots for key, as a bit mask.
func (s *scheduler) slots(p *schedProc, key string) uint32 {
	var m uint32
	for i := range p.state.Devices[:p.state.Num_devices] {
		if s.cfg.scope == ScopeNode || uuidKey(p.state.Devices[i].Uuid) == key {
			m |= 1 << i
		}
	}
	return m
}

// sampling reports whether p says it samples any of mask's slots.
func sampling(p *schedProc, mask uint32) bool {
	for i := range p.state.Devices[:p.state.Num_devices] {
		if mask&(1<<i) != 0 && p.state.Devices[i].Pc_state == pcOn {
			return true
		}
	}
	return false
}

// candidates maps each key to the processes that can PC sample it and ran
// kernels lately, by pid.
func (s *scheduler) candidates(now time.Time) map[string][]int {
	out := map[string][]int{}
	if s.cfg.noPCSampling {
		return out
	}
	for pid, p := range s.procs {
		if p.state.Pc_capable == 0 || now.Sub(p.lastActive) > activityWindow {
			continue
		}
		for i := range p.state.Devices[:p.state.Num_devices] {
			key := ScopeNode
			if s.cfg.scope != ScopeNode {
				key = uuidKey(p.state.Devices[i].Uuid)
			}
			if !slices.Contains(out[key], pid) {
				out[key] = append(out[key], pid)
			}
		}
	}
	for _, pids := range out {
		slices.Sort(pids)
	}
	return out
}

// next picks the candidate after last, in pid order.
func next(cands []int, last int) int {
	for _, pid := range cands {
		if pid > last {
			return pid
		}
	}
	return cands[0]
}

// tick advances every turn and writes each process's configuration where it
// changed. Call it periodically, after updating the processes' states.
func (s *scheduler) tick(now time.Time) {
	cands := s.candidates(now)
	for key := range cands {
		if s.turns[key] == nil {
			s.turns[key] = &turnState{}
		}
	}
	for key, t := range s.turns {
		s.advance(key, t, cands[key], now)
	}
	s.write()
	for key, t := range s.turns {
		s.holderGauge.WithLabelValues(key).Set(float64(t.pid))
		if t.pid == 0 && len(cands[key]) == 0 {
			delete(s.turns, key)
			s.holderGauge.DeleteLabelValues(key)
		}
	}
}

func (s *scheduler) advance(key string, t *turnState, cands []int, now time.Time) {
	if t.pid != 0 && !slices.Contains(cands, t.pid) {
		if s.procs[t.pid] == nil {
			// Exited: nothing left to release.
			t.last, t.pid, t.releasing = t.pid, 0, false
		} else if !t.releasing {
			// Idle: take the GPU back, as at the end of a turn.
			t.releasing, t.releaseAt, t.releaseGen = true, now, 0
		}
	}
	if t.releasing {
		p := s.procs[t.pid]
		switch {
		case t.releaseGen != 0 && p.appliedGen >= t.releaseGen && !sampling(p, s.slots(p, key)):
			t.last, t.pid, t.releasing = t.pid, 0, false
			s.rotations.Inc()
		case now.Sub(t.releaseAt) > handoverTimeout:
			s.timeouts.Inc()
			s.log.Warn("PC sampling hand-over timed out; holder keeps its turn",
				"gpu", key, "pid", t.pid)
			t.releasing, t.since = false, now
		}
	}
	if t.pid == 0 && len(cands) > 0 {
		// Whoever still samples here (a previous agent's holder, say) keeps
		// it if it is a candidate; else wait until it has stopped (it is told
		// to). Otherwise the next in turn.
		pid := next(cands, t.last)
		for c, p := range s.procs {
			if !sampling(p, s.slots(p, key)) {
				continue
			}
			if !slices.Contains(cands, c) {
				return
			}
			pid = c
		}
		t.pid, t.since = pid, now
		return
	}
	if t.pid != 0 && !t.releasing && len(cands) > 1 && now.Sub(t.since) >= s.cfg.turn {
		t.releasing, t.releaseAt, t.releaseGen = true, now, 0
	}
}

// write sends each process the configuration its turns call for, where it
// changed.
func (s *scheduler) write() {
	masks := map[int]uint32{}
	for key, t := range s.turns {
		if p := s.procs[t.pid]; p != nil && !t.releasing {
			masks[t.pid] |= s.slots(p, key)
		}
	}
	for pid, p := range s.procs {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, ctlConfig{
			Pc_sampling_devices:   masks[pid],
			Pc_sampling_factor:    s.cfg.factor,
			Pc_sampling_window_ms: s.cfg.windowMs,
			Pc_sampling_gap_ms:    s.cfg.gapMs,
			Rate_limit:            s.cfg.rateLimit,
			Graph_rate_limit:      s.cfg.graphRateLimit,
		})
		if p.written != nil && bytes.Equal(p.written, b.Bytes()) {
			continue
		}
		gen, err := p.t.Write(b.Bytes())
		if err != nil {
			s.log.Debug("writing configuration", "pid", pid, "err", err)
			continue
		}
		p.written, p.writtenGen = b.Bytes(), gen
		for _, t := range s.turns {
			if t.pid == pid && t.releasing && t.releaseGen == 0 {
				t.releaseGen = gen
			}
		}
	}
}
