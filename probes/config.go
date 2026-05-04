// Package probes attaches uprobes declared in a YAML config to user-space
// binaries observed by the agent and streams probe-fire events to the
// configured remote-store as OTLP/Arrow logs.
package probes

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// ProbeSpec is one entry parsed from the probe-config YAML, augmented with a
// 1-based spec_id assigned at parse time.
type ProbeSpec struct {
	SpecID      uint32
	Symbol      string
	FileMatch   string
	FileMatchRE *regexp.Regexp
}

type yamlConfig struct {
	Probes []yamlProbe `yaml:"probes"`
}

type yamlProbe struct {
	Symbol    string `yaml:"symbol"`
	FileMatch string `yaml:"file_match"`
}

// LoadConfig reads and parses a probe-config YAML file. Each entry must set
// both `symbol` and `file_match`; `file_match` is compiled as a Go regexp.
// SpecIDs are assigned in declaration order starting at 1.
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
		if p.Symbol == "" {
			return nil, fmt.Errorf("probes[%d]: `symbol` is required", i)
		}
		if p.FileMatch == "" {
			return nil, fmt.Errorf("probes[%d] (%s): `file_match` is required", i, p.Symbol)
		}
		re, err := regexp.Compile(p.FileMatch)
		if err != nil {
			return nil, fmt.Errorf("probes[%d] (%s): compile file_match %q: %w", i, p.Symbol, p.FileMatch, err)
		}
		specs = append(specs, ProbeSpec{
			SpecID:      uint32(i + 1),
			Symbol:      p.Symbol,
			FileMatch:   p.FileMatch,
			FileMatchRE: re,
		})
	}
	return specs, nil
}
