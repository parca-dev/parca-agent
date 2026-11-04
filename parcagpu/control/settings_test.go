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
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var base = Settings{
	PCSampling: true, Window: 30 * time.Millisecond, Gap: 270 * time.Millisecond,
	Turn: 10 * time.Second, Scope: ScopeGPU,
}

func TestParseSettings(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     func(*Settings)
		err      bool
	}{
		{"empty", "", func(*Settings) {}, false},
		{"comments only", "# nothing\n", func(*Settings) {}, false},
		{"some", "gap: 970ms\nrate_limit: 20\n", func(s *Settings) {
			s.Gap, s.RateLimit = 970*time.Millisecond, 20
		}, false},
		{"all", "pc_sampling: false\nfactor: 18\nwindow: 50ms\ngap: 2s\nturn: 30s\nscope: node\n" +
			"rate_limit: 10\ngraph_rate_limit: 5\n", func(s *Settings) {
			*s = Settings{Factor: 18, Window: 50 * time.Millisecond, Gap: 2 * time.Second,
				Turn: 30 * time.Second, Scope: ScopeNode, RateLimit: 10, GraphRateLimit: 5}
		}, false},
		{"json", `{"gap": "1s"}`, func(s *Settings) { s.Gap = time.Second }, false},
		{"unknown key", "gaps: 1s\n", nil, true},
		{"bad duration", "gap: 1\n", nil, true},
		{"out of range", "factor: 4\n", nil, true},
		{"bad scope", "scope: rack\n", nil, true},
		{"rate limit too high", "rate_limit: 1000001\n", nil, true},
	} {
		got, err := ParseSettings([]byte(tc.in), base)
		if (err != nil) != tc.err {
			t.Errorf("%s: err %v", tc.name, err)
			continue
		}
		if tc.err {
			continue
		}
		want := base
		tc.want(&want)
		if got != want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, want)
		}
	}
}

func testController() *Controller {
	return &Controller{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), base: base, settings: base,
		setCh: make(chan Settings, 1), gauges: newSettingsGauges(nil),
	}
}

func TestServeHTTP(t *testing.T) {
	c := testController()
	do := func(method, body string) (int, string) {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(method, "/gpu-control", strings.NewReader(body)))
		return w.Code, w.Body.String()
	}
	if code, body := do(http.MethodGet, ""); code != 200 || !strings.Contains(body, "gap: 270ms") {
		t.Fatalf("GET: %d %q", code, body)
	}
	if code, body := do(http.MethodPut, "gap: 970ms\n"); code != 200 || !strings.Contains(body, "gap: 970ms") {
		t.Fatalf("PUT: %d %q", code, body)
	}
	if got := <-c.setCh; got.Gap != 970*time.Millisecond {
		t.Fatalf("loop told %+v", got)
	}
	// Each request applies over the flags, not over the last request.
	if code, _ := do(http.MethodPut, "rate_limit: 50\n"); code != 200 || c.Settings().Gap != base.Gap {
		t.Fatalf("PUT 2: %d %+v", code, c.Settings())
	}
	if code, _ := do(http.MethodPut, "factor: 99\n"); code != http.StatusBadRequest || c.Settings().RateLimit != 50 {
		t.Fatalf("bad PUT: %d %+v", code, c.Settings())
	}
	if code, _ := do(http.MethodDelete, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: %d", code)
	}
}

func TestWatchFile(t *testing.T) {
	defer func(d time.Duration) { fileCheckInterval = d }(fileCheckInterval)
	fileCheckInterval = 10 * time.Millisecond
	c := testController()
	path := filepath.Join(t.TempDir(), "settings.yaml")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.WatchFile(ctx, path)

	eventually := func(what string, ok func(Settings) bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if ok(c.Settings()) {
				return
			}
		}
		t.Fatalf("%s: %+v", what, c.Settings())
	}
	write := func(s string) {
		// As kubelet updates a ConfigMap volume: a new file renamed over.
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}

	write("pc_sampling: false\ngap: 2s\n")
	eventually("file applied", func(s Settings) bool { return !s.PCSampling && s.Gap == 2*time.Second })
	write("gap: [\n")
	time.Sleep(50 * time.Millisecond)
	if s := c.Settings(); s.PCSampling || s.Gap != 2*time.Second {
		t.Fatalf("invalid file changed settings: %+v", s)
	}
	write("gap: 1s\n")
	eventually("pc_sampling back to the flag's", func(s Settings) bool { return s.PCSampling && s.Gap == time.Second })
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	eventually("file gone: the flags", func(s Settings) bool { return s == base })
}
