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
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

// MaxRateLimit is parcagpu's largest launch probe rate limit.
const MaxRateLimit = 1_000_000

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
}

// Validate reports settings parcagpu would reject, or the scheduler can't
// use.
func (s Settings) Validate() error {
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
	}
	return nil
}

func (s Settings) schedConfig() schedConfig {
	return schedConfig{
		factor:         s.Factor,
		windowMs:       uint32(s.Window.Milliseconds()),
		gapMs:          uint32(s.Gap.Milliseconds()),
		turn:           s.Turn,
		scope:          s.Scope,
		rateLimit:      s.RateLimit,
		graphRateLimit: s.GraphRateLimit,
		noPCSampling:   !s.PCSampling,
	}
}

// file is the settings file and request format: YAML (or JSON) with any of
// these keys. A key that is absent leaves the setting as the agent's flags
// say.
type file struct {
	PCSampling     *bool     `yaml:"pc_sampling"`
	Factor         *uint32   `yaml:"factor"`
	Window         *duration `yaml:"window"`
	Gap            *duration `yaml:"gap"`
	Turn           *duration `yaml:"turn"`
	Scope          *string   `yaml:"scope"`
	RateLimit      *uint32   `yaml:"rate_limit"`
	GraphRateLimit *uint32   `yaml:"graph_rate_limit"`
}

// duration is a time.Duration written as Go writes it ("30ms").
type duration time.Duration

func (d *duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	*d = duration(v)
	return err
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
	setDuration := func(dst *time.Duration, v *duration) {
		if v != nil {
			*dst = time.Duration(*v)
		}
	}
	if f.PCSampling != nil {
		s.PCSampling = *f.PCSampling
	}
	set(&s.Factor, f.Factor)
	setDuration(&s.Window, f.Window)
	setDuration(&s.Gap, f.Gap)
	setDuration(&s.Turn, f.Turn)
	if f.Scope != nil {
		s.Scope = *f.Scope
	}
	set(&s.RateLimit, f.RateLimit)
	set(&s.GraphRateLimit, f.GraphRateLimit)
	return s, s.Validate()
}

// String writes s in the settings file format.
func (s Settings) String() string {
	return fmt.Sprintf("pc_sampling: %t\nfactor: %d\nwindow: %v\ngap: %v\nturn: %v\nscope: %s\n"+
		"rate_limit: %d\ngraph_rate_limit: %d\n",
		s.PCSampling, s.Factor, s.Window, s.Gap, s.Turn, s.Scope, s.RateLimit, s.GraphRateLimit)
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
	if s == c.settings {
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

// settingsGauges exports the settings in effect.
type settingsGauges struct{ *prometheus.GaugeVec }

func newSettingsGauges(reg prometheus.Registerer) settingsGauges {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "parca_agent_gpu_control_setting",
		Help: "GPU control settings in effect (durations in seconds; pc_sampling 0 or 1).",
	}, []string{"setting"})
	if reg != nil {
		reg.MustRegister(g)
	}
	return settingsGauges{g}
}

func (g settingsGauges) set(s Settings) {
	pc := 0.0
	if s.PCSampling {
		pc = 1
	}
	g.WithLabelValues("pc_sampling").Set(pc)
	g.WithLabelValues("factor").Set(float64(s.Factor))
	g.WithLabelValues("window").Set(s.Window.Seconds())
	g.WithLabelValues("gap").Set(s.Gap.Seconds())
	g.WithLabelValues("turn").Set(s.Turn.Seconds())
	g.WithLabelValues("rate_limit").Set(float64(s.RateLimit))
	g.WithLabelValues("graph_rate_limit").Set(float64(s.GraphRateLimit))
}
