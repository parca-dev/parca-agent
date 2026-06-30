// Package probes attaches paired entry/exit uprobes declared in a YAML config
// to user-space binaries observed by the agent and streams scope-duration
// events to the configured remote-store as OTLP logs.
package probes

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// ProbeSpec is one entry parsed from the probe-config YAML, augmented with a
// 1-based spec_id assigned at parse time. Each spec describes a paired
// entry/exit uprobe pair whose duration is measured in BPF.
type ProbeSpec struct {
	SpecID         uint32
	ID             string
	FileMatch      string
	FileMatchRE    *regexp.Regexp
	EntrySymbol    string
	ExitSymbol     string
	MainThreadOnly bool
	MinDurationMs  uint32
}

// Cookie returns the 64-bit value passed via UprobeOptions.Cookie to both the
// entry and exit BPF programs. Layout:
//
//	bits 63..32 : spec_id  (uint32, 1-based)
//	bits 31..1  : min_duration_ms (31 bits, ~24 days max)
//	bit  0      : main_thread_only flag
func (s ProbeSpec) Cookie() uint64 {
	var low uint64
	if s.MainThreadOnly {
		low |= 1
	}
	low |= (uint64(s.MinDurationMs) & 0x7fffffff) << 1
	return (uint64(s.SpecID) << 32) | low
}

type yamlConfig struct {
	Probes []yamlProbe `yaml:"probes"`
}

type yamlProbe struct {
	ID             string `yaml:"id"`
	FileMatch      string `yaml:"file_match"`
	EntrySymbol    string `yaml:"entry_symbol"`
	ExitSymbol     string `yaml:"exit_symbol"`
	MainThreadOnly *bool  `yaml:"main_thread_only"` // pointer so we can detect "unset" vs "false"
	MinDurationMs  uint32 `yaml:"min_duration_ms"`
}

// LoadConfig reads and parses a probe-config YAML file. Required fields per
// entry: `id`, `file_match`, `entry_symbol`, `exit_symbol`. Defaults:
// main_thread_only=true, min_duration_ms=0.
//
// `file_match` is usually matched against the executable's absolute path
// (from args.Mapping.Path), but for cache catch-up and any code path where
// the absolute path is unavailable, the executable's basename is used as a
// fallback. Probe regexes should accept either form, e.g. `(^|/)node$`.
func LoadConfig(path string) ([]ProbeSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read probe config %s: %w", path, err)
	}
	return parseConfig(b)
}

func parseConfig(b []byte) ([]ProbeSpec, error) {
	var c yamlConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse probe config: %w", err)
	}
	if len(c.Probes) == 0 {
		return nil, fmt.Errorf("probe config has no `probes` entries")
	}
	specs := make([]ProbeSpec, 0, len(c.Probes))
	for i, p := range c.Probes {
		if p.ID == "" {
			return nil, fmt.Errorf("probes[%d]: `id` is required", i)
		}
		if p.FileMatch == "" {
			return nil, fmt.Errorf("probes[%d] (%s): `file_match` is required", i, p.ID)
		}
		if p.EntrySymbol == "" {
			return nil, fmt.Errorf("probes[%d] (%s): `entry_symbol` is required", i, p.ID)
		}
		if p.ExitSymbol == "" {
			return nil, fmt.Errorf("probes[%d] (%s): `exit_symbol` is required", i, p.ID)
		}
		re, err := regexp.Compile(p.FileMatch)
		if err != nil {
			return nil, fmt.Errorf("probes[%d] (%s): compile file_match %q: %w", i, p.ID, p.FileMatch, err)
		}
		mainThreadOnly := true
		if p.MainThreadOnly != nil {
			mainThreadOnly = *p.MainThreadOnly
		}
		specs = append(specs, ProbeSpec{
			SpecID:         uint32(i + 1),
			ID:             p.ID,
			FileMatch:      p.FileMatch,
			FileMatchRE:    re,
			EntrySymbol:    p.EntrySymbol,
			ExitSymbol:     p.ExitSymbol,
			MainThreadOnly: mainThreadOnly,
			MinDurationMs:  p.MinDurationMs,
		})
	}
	return specs, nil
}
