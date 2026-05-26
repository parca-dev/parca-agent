package probes

import (
	"testing"
)

func TestParseConfig_Valid(t *testing.T) {
	yaml := []byte(`
probes:
  - symbol: runtime.mallocgc
    file_match: '/usr/local/go/bin/.*'
  - symbol: pg_query
    file_match: '/usr/lib/postgresql/.*'
`)
	specs, err := parseConfig(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 specs, got %d", len(specs))
	}
	if specs[0].SpecID != 1 || specs[1].SpecID != 2 {
		t.Errorf("spec IDs not 1-based sequential: %v %v", specs[0].SpecID, specs[1].SpecID)
	}
	if !specs[0].FileMatchRE.MatchString("/usr/local/go/bin/go") {
		t.Errorf("regex did not match expected path")
	}
	if specs[0].FileMatchRE.MatchString("/bin/sh") {
		t.Errorf("regex matched unexpected path")
	}
}

func TestParseConfig_MissingSymbol(t *testing.T) {
	yaml := []byte(`
probes:
  - file_match: '/usr/bin/.*'
`)
	if _, err := parseConfig(yaml); err == nil {
		t.Fatal("expected error for missing symbol")
	}
}

func TestParseConfig_MissingFileMatch(t *testing.T) {
	yaml := []byte(`
probes:
  - symbol: foo
`)
	if _, err := parseConfig(yaml); err == nil {
		t.Fatal("expected error for missing file_match")
	}
}

func TestParseConfig_InvalidRegex(t *testing.T) {
	yaml := []byte(`
probes:
  - symbol: foo
    file_match: '['
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
