package probes

import (
	"testing"
)

func TestParseConfig_Valid(t *testing.T) {
	yaml := []byte(`
probes:
  - id: node.callback_scope
    file_match: '(^|/)node$'
    entry_symbol: _ZN4node21InternalCallbackScopeC1EPNS_9AsyncWrapEi
    exit_symbol:  _ZN4node21InternalCallbackScopeD1Ev
`)
	specs, err := parseConfig(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("want 1 spec, got %d", len(specs))
	}
	s := specs[0]
	if s.SpecID != 1 {
		t.Errorf("spec id not 1: %d", s.SpecID)
	}
	if s.ID != "node.callback_scope" {
		t.Errorf("id = %q", s.ID)
	}
	if !s.FileMatchRE.MatchString("/usr/bin/node") {
		t.Errorf("regex did not match full path")
	}
	if !s.FileMatchRE.MatchString("node") {
		t.Errorf("regex did not match bare basename")
	}
	if s.FileMatchRE.MatchString("libpipewire-module-client-node.so") {
		t.Errorf("regex matched lib ending in -node.so")
	}
	if s.FileMatchRE.MatchString("/bin/sh") {
		t.Errorf("regex matched unexpected path")
	}
	if !s.MainThreadOnly {
		t.Errorf("main_thread_only default should be true")
	}
	if s.MinDurationMs != 0 {
		t.Errorf("min_duration_ms default should be 0, got %d", s.MinDurationMs)
	}
}

func TestParseConfig_ExplicitOverrides(t *testing.T) {
	yaml := []byte(`
probes:
  - id: node.cb
    file_match: '.*/node$'
    entry_symbol: foo
    exit_symbol: bar
    main_thread_only: false
    min_duration_ms: 50
`)
	specs, err := parseConfig(yaml)
	if err != nil {
		t.Fatal(err)
	}
	s := specs[0]
	if s.MainThreadOnly {
		t.Errorf("main_thread_only should be false")
	}
	if s.MinDurationMs != 50 {
		t.Errorf("min_duration_ms = %d, want 50", s.MinDurationMs)
	}
}

func TestParseConfig_Cookie(t *testing.T) {
	cases := []struct {
		spec ProbeSpec
		want uint64
	}{
		{ProbeSpec{SpecID: 1, MainThreadOnly: true, MinDurationMs: 0}, (1 << 32) | 1},
		{ProbeSpec{SpecID: 2, MainThreadOnly: false, MinDurationMs: 0}, 2 << 32},
		{ProbeSpec{SpecID: 3, MainThreadOnly: true, MinDurationMs: 50}, (3 << 32) | (50 << 1) | 1},
		{ProbeSpec{SpecID: 4, MainThreadOnly: false, MinDurationMs: 100}, (4 << 32) | (100 << 1)},
	}
	for _, c := range cases {
		got := c.spec.Cookie()
		if got != c.want {
			t.Errorf("Cookie(spec=%+v) = %#x, want %#x", c.spec, got, c.want)
		}
	}
}

func TestParseConfig_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing id", `probes: [{file_match: '.*', entry_symbol: a, exit_symbol: b}]`},
		{"missing file_match", `probes: [{id: x, entry_symbol: a, exit_symbol: b}]`},
		{"missing entry_symbol", `probes: [{id: x, file_match: '.*', exit_symbol: b}]`},
		{"missing exit_symbol", `probes: [{id: x, file_match: '.*', entry_symbol: a}]`},
	}
	for _, c := range cases {
		if _, err := parseConfig([]byte(c.yaml)); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestParseConfig_InvalidRegex(t *testing.T) {
	yaml := []byte(`
probes:
  - id: x
    file_match: '['
    entry_symbol: a
    exit_symbol: b
`)
	if _, err := parseConfig(yaml); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestParseConfig_Empty(t *testing.T) {
	if _, err := parseConfig([]byte(`probes: []`)); err == nil {
		t.Fatal("expected error for empty probe list")
	}
}
