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

	"github.com/prometheus/client_golang/prometheus/testutil"
)

var base = Settings{
	PCSampling: true, Window: 30 * time.Millisecond, Gap: 270 * time.Millisecond,
	Turn: 10 * time.Second, Scope: ScopeGPU, KernelStats: true,
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
			"rate_limit: 10\ngraph_rate_limit: 5\nkernel_stats: false\nblocking_calls: true\n", func(s *Settings) {
			*s = Settings{Factor: 18, Window: 50 * time.Millisecond, Gap: 2 * time.Second,
				Turn: 30 * time.Second, Scope: ScopeNode, RateLimit: 10, GraphRateLimit: 5,
				BlockingCalls: true}
		}, false},
		{"features", "blocking_calls: true\n", func(s *Settings) { s.BlockingCalls = true }, false},
		{"bad bool", "kernel_stats: maybe\n", nil, true},
		{"v3", "pc_hw_buffer_mb: 64\nmetadata_refresh: 5s\nblocking_threshold: 50us\n", func(s *Settings) {
			s.PCHWBufferMB, s.MetadataRefresh, s.BlockingThreshold = 64, 5*time.Second, 50*time.Microsecond
		}, false},
		{"v3 maxima", "pc_hw_buffer_mb: 4096\nblocking_threshold: 1s\n", func(s *Settings) {
			s.PCHWBufferMB, s.BlockingThreshold = 4096, time.Second
		}, false},
		{"buffer too big", "pc_hw_buffer_mb: 4097\n", nil, true},
		{"threshold too long", "blocking_threshold: 1001ms\n", nil, true},
		{"threshold under 1us", "blocking_threshold: 500ns\n", nil, true},
		{"refresh under 1ms", "metadata_refresh: 1500us\n", nil, true},
		{"refresh negative", "metadata_refresh: -1s\n", nil, true},
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
		if !got.Equal(want) {
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
	eventually("file gone: the flags", func(s Settings) bool { return s.Equal(base) })
}

func TestParseWorkloads(t *testing.T) {
	in := `factor: 15
workloads:
  - name: vllm
    factor: 20
    rate_limit: 1000
  - name: vllm
    namespace: ml
    window: 50ms
  - name: batch
    pc_sampling: false
    kernel_stats: false
    blocking_calls: true
    blocking_threshold: 100us
    metadata_refresh: 2s
    pc_hw_buffer_mb: 32
`
	got, err := ParseSettings([]byte(in), base)
	if err != nil {
		t.Fatal(err)
	}
	f20, f15, rl, w50, off, on := uint32(20), uint32(15), uint32(1000), 50*time.Millisecond, false, true
	bt, mr, hw := 100*time.Microsecond, 2*time.Second, uint32(32)
	want := base
	want.Factor = f15
	want.Workloads = []WorkloadSettings{
		{Name: "vllm", Factor: &f20, RateLimit: &rl},
		{Name: "vllm", Namespace: "ml", Window: &w50},
		{Name: "batch", PCSampling: &off, KernelStats: &off, BlockingCalls: &on,
			BlockingThreshold: &bt, MetadataRefresh: &mr, PCHWBufferMB: &hw},
	}
	if !got.Equal(want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// What GET shows parses back to the same settings.
	again, err := ParseSettings([]byte(got.String()), Settings{})
	if err != nil || !again.Equal(got) {
		t.Fatalf("round trip: %v\n%s\n%+v", err, got.String(), again)
	}
	// Unset overrides follow the global setting.
	if s := want.Workloads[1].over(want); s.Factor != 15 || s.Window != w50 || !s.KernelStats {
		t.Fatalf("over: %+v", s)
	}
	// Features become the bits each workload's processes are told.
	c := got.schedConfig()
	if f := c.features; f != featureKernelStats {
		t.Errorf("global features %b", f)
	}
	if ps := c.workloads[2].settings; ps.features != featureBlockingCalls || ps.blockingThresholdUs != 100 ||
		ps.metadataRefreshMs != 2000 || ps.pcHWBufferMB != 32 {
		t.Errorf("batch: %+v", ps)
	}
	if ps := c.procSettings; ps.blockingThresholdUs != 0 || ps.metadataRefreshMs != 0 || ps.pcHWBufferMB != 0 {
		t.Errorf("global v3 knobs not left to the process: %+v", ps)
	}

	for _, bad := range []string{
		"workloads:\n  - factor: 20\n",                                               // no name
		"workloads:\n  - name: a\n  - name: a\n",                                     // twice
		"workloads:\n  - name: a\n    factor: 4\n",                                   // out of range
		"workloads:\n  - name: a\n    turn: 1s\n",                                    // global only
		"workloads:\n  - name: a\n    scope: node\n",                                 // global only
		"workloads:\n  - name: a\n    gaps: 1s\n",                                    // unknown key
		"window: 20s\nworkloads:\n  - name: a\n    window: 30ms\n",                   // global out of range
		"workloads:\n  - name: a\n    window: 11s\n",                                 // workload out of range
		"workloads:\n  - name: a\n    rate_limit: 1000001\n",                         // too high
		"workloads:\n  - name: a\n    blocking_threshold: 2s\n",                      // too long
		"workloads:\n  - name: a\n    namespace: x\n  - name: a\n    namespace: x\n", // twice
	} {
		if _, err := ParseSettings([]byte(bad), base); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// Same name, different namespaces: fine.
	if _, err := ParseSettings([]byte("workloads:\n  - name: a\n  - name: a\n    namespace: x\n"), base); err != nil {
		t.Error(err)
	}
}

func TestSettingsGauges(t *testing.T) {
	g := newSettingsGauges(nil)
	f20 := uint32(20)
	s := base
	s.Factor = 12
	s.Workloads = []WorkloadSettings{{Name: "vllm", Namespace: "ml", Factor: &f20}}
	g.set(s)
	for _, tc := range []struct {
		setting, workload string
		want              float64
	}{
		{"factor", "", 12},
		{"factor", "ml/vllm", 20},
		{"gap", "ml/vllm", base.Gap.Seconds()}, // not overridden: the global one
		{"turn", "", base.Turn.Seconds()},
		{"kernel_stats", "", 1},
		{"kernel_stats", "ml/vllm", 1},
		{"blocking_calls", "", 0},
	} {
		if got := testutil.ToFloat64(g.WithLabelValues(tc.setting, tc.workload)); got != tc.want {
			t.Errorf("%s{workload=%q} = %v, want %v", tc.setting, tc.workload, got, tc.want)
		}
	}
	// Workloads that go away take their series with them; turn is global only.
	s.Workloads = nil
	g.set(s)
	if n := testutil.CollectAndCount(g); n != 12 {
		t.Errorf("%d series after dropping the workload, want 12", n)
	}
}
