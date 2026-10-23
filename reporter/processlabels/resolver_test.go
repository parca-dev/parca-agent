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

package processlabels

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

func TestDefaultSemconvAttributes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		semconv bool
		rules   []*relabel.Config
	}{
		{name: "OTLP without config", semconv: true},
		{name: "arrow unchanged"},
		{
			name: "user rules override and drop defaults", semconv: true,
			rules: []*relabel.Config{
				{Action: relabel.Replace, Regex: relabel.MustNewRegexp(".*"), TargetLabel: "host.arch", Replacement: "overridden"},
				{Action: relabel.LabelDrop, Regex: relabel.MustNewRegexp("os.version")},
				{Action: relabel.Replace, SourceLabels: []model.LabelName{"__meta_process_executable_name"}, Regex: relabel.MustNewRegexp("(.+)"), TargetLabel: "source.executable", Replacement: "$1"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			execs, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](16, libpf.FileID.Hash32)
			require.NoError(t, err)
			fileID, err := libpf.FileIDFromExecutableFile("/proc/self/exe")
			require.NoError(t, err)
			execs.Add(fileID, metadata.ExecInfo{FileName: "/usr/bin/checkout"})
			providers, err := DefaultProviders(context.Background(), "node-7", "test", execs, metadata.Config{
				LocalOnly: true, Semconv: tc.semconv, KeepDiscoveryLabels: len(tc.rules) > 0,
			})
			require.NoError(t, err)
			r, err := New(Config{CacheSize: 16, LabelTTL: time.Minute, Providers: providers, RelabelConfigs: tc.rules})
			require.NoError(t, err)
			res := r.Resolve(context.Background(), libpf.PID(os.Getpid()), nil)
			require.True(t, res.Keep)
			attrs := pcommon.NewMap()
			PutProcessAttributes(attrs, Process{Labels: res.Labels, PID: 123, ServiceName: "declared-service"}, "node-7", true)
			got := attrs.AsRaw()
			require.Equal(t, "declared-service", got["service.name"])
			require.NotContains(t, got, "process.command_line", "command lines remain opt-in")
			require.NotEmpty(t, res.Labels.Get("comm"), "GPU and NVTX service naming needs the original comm")
			if !tc.semconv {
				require.NotContains(t, got, "host.arch")
				require.NotContains(t, got, "process.parent_pid")
				return
			}
			require.Equal(t, int64(os.Getppid()), got["process.parent_pid"])
			require.Equal(t, "checkout", got["process.executable.name"])
			require.Equal(t, "linux", got["os.type"])
			if len(tc.rules) > 0 {
				require.Equal(t, "overridden", got["host.arch"])
				require.NotContains(t, got, "os.version")
				require.Equal(t, "/usr/bin/checkout", got["source.executable"])
			} else {
				require.Equal(t, runtime.GOARCH, got["host.arch"])
				require.NotEmpty(t, got["os.version"])
			}
			res.Labels.Range(func(l labels.Label) { require.NotContains(t, l.Name, "__meta_") })
		})
	}
}

// TestForkIsolatesCache checks a fork applies the same relabel rules but
// doesn't see results cached under the parent's seed.
func TestForkIsolatesCache(t *testing.T) {
	keepOOM := &relabel.Config{
		Action: relabel.Keep, SourceLabels: []model.LabelName{"job"},
		Regex: relabel.MustNewRegexp("oomprof"), Separator: ";",
	}
	parent, err := New(Config{CacheSize: 16, LabelTTL: time.Minute, NodeName: "n", RelabelConfigs: []*relabel.Config{keepOOM}})
	require.NoError(t, err)
	fork, err := parent.Fork()
	require.NoError(t, err)
	require.Equal(t, parent.RelabelConfigs(), fork.RelabelConfigs())

	res := parent.Resolve(context.Background(), 42, func(lb *labels.Builder) { lb.Set("job", "oomprof") })
	require.True(t, res.Keep)

	res = fork.Resolve(context.Background(), 42, nil)
	require.False(t, res.Keep, "the fork resolves pid 42 itself, without the parent's seed")
}
