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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

// Bounds parcagpu puts on settings.
const (
	// MaxRateLimit is the largest launch probe rate limit.
	MaxRateLimit = 1_000_000
	// MaxPCHWBufferMB is the largest PC sampling hardware buffer, MB.
	MaxPCHWBufferMB = 4096
	// MaxBlockingThreshold is the largest cuda_blocking_call threshold.
	MaxBlockingThreshold = time.Second
	// maxMetadataRefresh fits parcagpu_ctl_config.metadata_refresh_ms.
	maxMetadataRefresh = math.MaxUint32 * time.Millisecond
)

// Settings are what the controller tells every process, and how turns
// rotate. They can change while it runs: Set, WatchFile, ServeHTTP.
type Settings struct {
	// PCSampling: whether processes take turns at PC sampling. Without it,
	// none samples, whatever its environment says.
	PCSampling bool
	// Factor is the CUPTI sampling factor (period 2^Factor cycles), 5-31; 0
	// leaves it to each process.
	Factor uint32
	// Window is how long each PC sampling window stays open, 1ms-10s.
	Window time.Duration
	// Gap is the pause between windows on a GPU, up to 60s: the duty cycle
	// is Window/(Window+Gap).
	Gap time.Duration
	// Turn is how long a process keeps a GPU while others wait for it.
	Turn time.Duration
	// Scope is ScopeGPU or ScopeNode.
	Scope string
	// RateLimit and GraphRateLimit are the launch probe rate limits, events
	// per second per thread, for kernel and CUDA graph launches, up to
	// MaxRateLimit; 0 leaves them to each process (PARCAGPU_RATE_LIMIT,
	// PARCAGPU_GRAPH_RATE_LIMIT).
	RateLimit      uint32
	GraphRateLimit uint32
	// KernelStats turns on parcagpu's kernel_stats probe: exact kernel
	// execution counts and durations, counted before the launch rate limits.
	// Under the agent it is off unless set (PARCAGPU_FEATURE_KERNEL_STATS).
	KernelStats bool
	// BlockingCalls turns on parcagpu's cuda_blocking_call probe: host time
	// blocked in CUDA API calls. Its callbacks run on every covered API call,
	// so it costs more than the rest (PARCAGPU_FEATURE_BLOCKING_CALLS).
	BlockingCalls bool

	// The knobs below need control schema version 3; a version 2 process
	// keeps its environment's. 0 leaves each to the process.

	// PCHWBufferMB is CUPTI's PC sampling hardware buffer, MB, up to
	// MaxPCHWBufferMB (as PARCAGPU_PC_HW_BUFFER_MB). A context takes it at
	// its next setup for PC sampling.
	PCHWBufferMB uint32
	// MetadataRefresh is how often processes re-emit cubins, the stall
	// reason map and their GPU configuration (as
	// PARCAGPU_METADATA_REFRESH_MS), in whole milliseconds.
	MetadataRefresh time.Duration
	// BlockingThreshold is the cuda_blocking_call threshold, in whole
	// microseconds up to MaxBlockingThreshold (as
	// PARCAGPU_BLOCKING_THRESHOLD_US): calls blocked at least this long are
	// reported, shorter ones with probability duration/threshold.
	BlockingThreshold time.Duration

	// Workloads override the settings above for the processes of some
	// workloads. A process matches no more than one; one that matches none
	// keeps the settings above.
	Workloads []WorkloadSettings
}

// WorkloadSettings override the global Settings for the processes of one
// workload, matched by the OTel service.name the process declares
// (OTEL_SERVICE_NAME, service.name in OTEL_RESOURCE_ATTRIBUTES, or its
// process context) or, failing that, the one OTel infers from its
// Kubernetes pod. Each field that is set replaces the global setting. Turn
// and Scope are about sharing a GPU between processes, so only the global
// ones apply.
type WorkloadSettings struct {
	Name string
	// Namespace, if set, narrows Name to processes whose service.namespace
	// or Kubernetes namespace it is. A rule with a Namespace beats one
	// without.
	Namespace string

	PCSampling     *bool
	Factor         *uint32
	Window         *time.Duration
	Gap            *time.Duration
	RateLimit      *uint32
	GraphRateLimit *uint32
	KernelStats    *bool
	BlockingCalls  *bool

	PCHWBufferMB      *uint32
	MetadataRefresh   *time.Duration
	BlockingThreshold *time.Duration
}

// Label is how metrics and logs name w: "namespace/name", or "name".
func (w WorkloadSettings) Label() string {
	if w.Namespace == "" {
		return w.Name
	}
	return w.Namespace + "/" + w.Name
}

// over returns s with w's overrides applied.
func (w WorkloadSettings) over(s Settings) Settings {
	if w.PCSampling != nil {
		s.PCSampling = *w.PCSampling
	}
	if w.Factor != nil {
		s.Factor = *w.Factor
	}
	if w.Window != nil {
		s.Window = *w.Window
	}
	if w.Gap != nil {
		s.Gap = *w.Gap
	}
	if w.RateLimit != nil {
		s.RateLimit = *w.RateLimit
	}
	if w.GraphRateLimit != nil {
		s.GraphRateLimit = *w.GraphRateLimit
	}
	if w.KernelStats != nil {
		s.KernelStats = *w.KernelStats
	}
	if w.BlockingCalls != nil {
		s.BlockingCalls = *w.BlockingCalls
	}
	if w.PCHWBufferMB != nil {
		s.PCHWBufferMB = *w.PCHWBufferMB
	}
	if w.MetadataRefresh != nil {
		s.MetadataRefresh = *w.MetadataRefresh
	}
	if w.BlockingThreshold != nil {
		s.BlockingThreshold = *w.BlockingThreshold
	}
	s.Workloads = nil
	return s
}

// Equal reports whether s and o are the same settings.
func (s Settings) Equal(o Settings) bool { return reflect.DeepEqual(s, o) }

// Validate reports settings parcagpu would reject, or the scheduler can't
// use.
func (s Settings) Validate() error {
	if err := s.validateGlobal(); err != nil {
		return err
	}
	seen := map[[2]string]bool{}
	for _, w := range s.Workloads {
		if w.Name == "" {
			return errors.New("workload without a name")
		}
		key := [2]string{w.Namespace, w.Name}
		if seen[key] {
			return fmt.Errorf("workload %q appears twice", w.Label())
		}
		seen[key] = true
		if err := w.over(s).validateGlobal(); err != nil {
			return fmt.Errorf("workload %q: %w", w.Label(), err)
		}
	}
	return nil
}

func (s Settings) validateGlobal() error {
	switch {
	case s.Factor != 0 && (s.Factor < 5 || s.Factor > 31):
		return fmt.Errorf("factor %d out of range (5-31, or 0)", s.Factor)
	case s.Window < time.Millisecond || s.Window > 10*time.Second:
		return fmt.Errorf("window %v out of range (1ms-10s)", s.Window)
	case s.Gap < 0 || s.Gap > time.Minute:
		return fmt.Errorf("gap %v out of range (0-60s)", s.Gap)
	case s.Turn <= 0:
		return fmt.Errorf("turn %v must be positive", s.Turn)
	case s.Scope != ScopeGPU && s.Scope != ScopeNode:
		return fmt.Errorf("scope %q is neither %q nor %q", s.Scope, ScopeGPU, ScopeNode)
	case s.RateLimit > MaxRateLimit || s.GraphRateLimit > MaxRateLimit:
		return fmt.Errorf("rate limits %d, %d: at most %d", s.RateLimit, s.GraphRateLimit, MaxRateLimit)
	case s.PCHWBufferMB > MaxPCHWBufferMB:
		return fmt.Errorf("pc_hw_buffer_mb %d: at most %d", s.PCHWBufferMB, MaxPCHWBufferMB)
	case s.MetadataRefresh < 0 || s.MetadataRefresh > maxMetadataRefresh || s.MetadataRefresh%time.Millisecond != 0:
		return fmt.Errorf("metadata_refresh %v: whole milliseconds, up to %v, or 0", s.MetadataRefresh, maxMetadataRefresh)
	case s.BlockingThreshold < 0 || s.BlockingThreshold > MaxBlockingThreshold ||
		s.BlockingThreshold%time.Microsecond != 0:
		return fmt.Errorf("blocking_threshold %v: whole microseconds, up to %v, or 0",
			s.BlockingThreshold, MaxBlockingThreshold)
	}
	return nil
}

func (s Settings) procSettings() procSettings {
	var features uint32
	if s.KernelStats {
		features |= featureKernelStats
	}
	if s.BlockingCalls {
		features |= featureBlockingCalls
	}
	return procSettings{
		factor:         s.Factor,
		windowMs:       uint32(s.Window.Milliseconds()),
		gapMs:          uint32(s.Gap.Milliseconds()),
		rateLimit:      s.RateLimit,
		graphRateLimit: s.GraphRateLimit,
		features:       features,
		noPCSampling:   !s.PCSampling,

		pcHWBufferMB:        s.PCHWBufferMB,
		metadataRefreshMs:   uint32(s.MetadataRefresh.Milliseconds()),
		blockingThresholdUs: uint32(s.BlockingThreshold.Microseconds()),
	}
}

func (s Settings) schedConfig() schedConfig {
	c := schedConfig{procSettings: s.procSettings(), turn: s.Turn, scope: s.Scope}
	for _, w := range s.Workloads {
		c.workloads = append(c.workloads, workloadRule{
			name: w.Name, namespace: w.Namespace, label: w.Label(),
			settings: w.over(s).procSettings(),
		})
	}
	return c
}

// file is the settings file and request format: YAML (or JSON) with any of
// these keys. A key that is absent leaves the setting as the agent's flags
// say; workloads, which no flag sets, is the whole list.
type file struct {
	PCSampling     *bool     `yaml:"pc_sampling"`
	Factor         *uint32   `yaml:"factor"`
	Window         *duration `yaml:"window"`
	Gap            *duration `yaml:"gap"`
	Turn           *duration `yaml:"turn"`
	Scope          *string   `yaml:"scope"`
	RateLimit      *uint32   `yaml:"rate_limit"`
	GraphRateLimit *uint32   `yaml:"graph_rate_limit"`
	KernelStats    *bool     `yaml:"kernel_stats"`
	BlockingCalls  *bool     `yaml:"blocking_calls"`

	PCHWBufferMB      *uint32   `yaml:"pc_hw_buffer_mb"`
	MetadataRefresh   *duration `yaml:"metadata_refresh"`
	BlockingThreshold *duration `yaml:"blocking_threshold"`

	Workloads []workloadFile `yaml:"workloads,omitempty"`
}

// workloadFile is one entry of the file's workloads.
type workloadFile struct {
	Name           string    `yaml:"name"`
	Namespace      string    `yaml:"namespace,omitempty"`
	PCSampling     *bool     `yaml:"pc_sampling,omitempty"`
	Factor         *uint32   `yaml:"factor,omitempty"`
	Window         *duration `yaml:"window,omitempty"`
	Gap            *duration `yaml:"gap,omitempty"`
	RateLimit      *uint32   `yaml:"rate_limit,omitempty"`
	GraphRateLimit *uint32   `yaml:"graph_rate_limit,omitempty"`
	KernelStats    *bool     `yaml:"kernel_stats,omitempty"`
	BlockingCalls  *bool     `yaml:"blocking_calls,omitempty"`

	PCHWBufferMB      *uint32   `yaml:"pc_hw_buffer_mb,omitempty"`
	MetadataRefresh   *duration `yaml:"metadata_refresh,omitempty"`
	BlockingThreshold *duration `yaml:"blocking_threshold,omitempty"`

	// Only to reject them with a better reason than an unknown key.
	Turn  *duration `yaml:"turn,omitempty"`
	Scope *string   `yaml:"scope,omitempty"`
}

// duration is a time.Duration written as Go writes it ("30ms").
type duration time.Duration

func (d *duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	*d = duration(v)
	return err
}

func (d duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func durationPtr(d *duration) *time.Duration {
	if d == nil {
		return nil
	}
	v := time.Duration(*d)
	return &v
}

func filePtr(d *time.Duration) *duration {
	if d == nil {
		return nil
	}
	v := duration(*d)
	return &v
}

// ParseSettings applies the settings in b, in the settings file format, over
// base.
func ParseSettings(b []byte, base Settings) (Settings, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return base, err
	}
	s := base
	set := func(dst *uint32, v *uint32) {
		if v != nil {
			*dst = *v
		}
	}
	setBool := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	setDuration := func(dst *time.Duration, v *duration) {
		if v != nil {
			*dst = time.Duration(*v)
		}
	}
	setBool(&s.PCSampling, f.PCSampling)
	set(&s.Factor, f.Factor)
	setDuration(&s.Window, f.Window)
	setDuration(&s.Gap, f.Gap)
	setDuration(&s.Turn, f.Turn)
	if f.Scope != nil {
		s.Scope = *f.Scope
	}
	set(&s.RateLimit, f.RateLimit)
	set(&s.GraphRateLimit, f.GraphRateLimit)
	setBool(&s.KernelStats, f.KernelStats)
	setBool(&s.BlockingCalls, f.BlockingCalls)
	set(&s.PCHWBufferMB, f.PCHWBufferMB)
	setDuration(&s.MetadataRefresh, f.MetadataRefresh)
	setDuration(&s.BlockingThreshold, f.BlockingThreshold)
	if f.Workloads != nil {
		s.Workloads = nil
	}
	for _, w := range f.Workloads {
		if w.Turn != nil || w.Scope != nil {
			return base, fmt.Errorf("workload %q: turn and scope are about sharing a GPU, "+
				"so they can only be set for every workload, at the top level", w.Name)
		}
		s.Workloads = append(s.Workloads, WorkloadSettings{
			Name: w.Name, Namespace: w.Namespace,
			PCSampling: w.PCSampling, Factor: w.Factor,
			Window: durationPtr(w.Window), Gap: durationPtr(w.Gap),
			RateLimit: w.RateLimit, GraphRateLimit: w.GraphRateLimit,
			KernelStats: w.KernelStats, BlockingCalls: w.BlockingCalls,
			PCHWBufferMB:    w.PCHWBufferMB,
			MetadataRefresh: durationPtr(w.MetadataRefresh), BlockingThreshold: durationPtr(w.BlockingThreshold),
		})
	}
	return s, s.Validate()
}

// String writes s in the settings file format.
func (s Settings) String() string {
	window, gap, turn := duration(s.Window), duration(s.Gap), duration(s.Turn)
	refresh, threshold := duration(s.MetadataRefresh), duration(s.BlockingThreshold)
	f := file{
		PCSampling: &s.PCSampling, Factor: &s.Factor, Window: &window, Gap: &gap, Turn: &turn,
		Scope: &s.Scope, RateLimit: &s.RateLimit, GraphRateLimit: &s.GraphRateLimit,
		KernelStats: &s.KernelStats, BlockingCalls: &s.BlockingCalls,
		PCHWBufferMB: &s.PCHWBufferMB, MetadataRefresh: &refresh, BlockingThreshold: &threshold,
	}
	for _, w := range s.Workloads {
		f.Workloads = append(f.Workloads, workloadFile{
			Name: w.Name, Namespace: w.Namespace,
			PCSampling: w.PCSampling, Factor: w.Factor,
			Window: filePtr(w.Window), Gap: filePtr(w.Gap),
			RateLimit: w.RateLimit, GraphRateLimit: w.GraphRateLimit,
			KernelStats: w.KernelStats, BlockingCalls: w.BlockingCalls,
			PCHWBufferMB:    w.PCHWBufferMB,
			MetadataRefresh: filePtr(w.MetadataRefresh), BlockingThreshold: filePtr(w.BlockingThreshold),
		})
	}
	b, err := yaml.Marshal(f)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// Settings returns the settings in effect.
func (c *Controller) Settings() Settings {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	return c.settings
}

// Set changes the settings. Every process is told at the next tick; a change
// of scope, or turning PC sampling off, hands GPUs back as at the end of a
// turn.
func (c *Controller) Set(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if s.Equal(c.settings) {
		return nil
	}
	c.settings = s
	select { // replace a change loop hasn't taken yet
	case <-c.setCh:
	default:
	}
	c.setCh <- s
	return nil
}

// fileCheckInterval is how often WatchFile reads the file.
var fileCheckInterval = 5 * time.Second

// WatchFile applies the settings file at path over the flags' settings
// (Options.Settings), now and whenever its content changes, until ctx ends.
// A missing file means no changes; an invalid one is logged and ignored.
// Mounted from a Kubernetes ConfigMap (as a directory, not with subPath),
// it follows edits to the ConfigMap within about a minute.
func (c *Controller) WatchFile(ctx context.Context, path string) {
	var last [sha256.Size]byte
	first := true
	check := func() {
		b, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			c.log.Warn("reading GPU control settings", "path", path, "err", err)
			return
		}
		sum := sha256.Sum256(b)
		if !first && sum == last {
			return
		}
		first, last = false, sum
		s, err := ParseSettings(b, c.base)
		if err == nil {
			err = c.Set(s)
		}
		if err != nil {
			c.log.Warn("ignoring GPU control settings", "path", path, "err", err)
		}
	}
	check()
	tick := time.NewTicker(fileCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			check()
		}
	}
}

// ServeHTTP shows the settings in effect (GET) and changes them (PUT, a body
// in the settings file format applied over the flags' settings). A later
// change to the settings file replaces them again.
func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut, http.MethodPost:
		b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		var s Settings
		if err == nil {
			s, err = ParseSettings(b, c.base)
		}
		if err == nil {
			err = c.Set(s)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = io.WriteString(w, c.Settings().String())
}

// settingsGauges exports the settings in effect: the global ones with an
// empty workload label, and what each workload's processes are told.
type settingsGauges struct{ *prometheus.GaugeVec }

func newSettingsGauges(reg prometheus.Registerer) settingsGauges {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "parca_agent_gpu_control_setting",
		Help: "GPU control settings in effect, globally (workload \"\") and for each configured workload " +
			"(durations in seconds; pc_sampling, kernel_stats and blocking_calls 0 or 1). turn is only global.",
	}, []string{"setting", "workload"})
	if reg != nil {
		reg.MustRegister(g)
	}
	return settingsGauges{g}
}

func (g settingsGauges) set(s Settings) {
	g.Reset()
	g.setFor("", s)
	g.WithLabelValues("turn", "").Set(s.Turn.Seconds())
	for _, w := range s.Workloads {
		g.setFor(w.Label(), w.over(s))
	}
}

func (g settingsGauges) setFor(workload string, s Settings) {
	b := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	g.WithLabelValues("pc_sampling", workload).Set(b(s.PCSampling))
	g.WithLabelValues("factor", workload).Set(float64(s.Factor))
	g.WithLabelValues("window", workload).Set(s.Window.Seconds())
	g.WithLabelValues("gap", workload).Set(s.Gap.Seconds())
	g.WithLabelValues("rate_limit", workload).Set(float64(s.RateLimit))
	g.WithLabelValues("graph_rate_limit", workload).Set(float64(s.GraphRateLimit))
	g.WithLabelValues("kernel_stats", workload).Set(b(s.KernelStats))
	g.WithLabelValues("blocking_calls", workload).Set(b(s.BlockingCalls))
	g.WithLabelValues("pc_hw_buffer_mb", workload).Set(float64(s.PCHWBufferMB))
	g.WithLabelValues("metadata_refresh", workload).Set(s.MetadataRefresh.Seconds())
	g.WithLabelValues("blocking_threshold", workload).Set(s.BlockingThreshold.Seconds())
}
