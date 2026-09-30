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

package reporter

import (
	"bytes"
	"os"
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	otelmetrics "go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// fileProcess serves one in-memory file for every mapping. Embedding the
// interface leaves every other method nil; ReportExecutable only opens files.
type fileProcess struct {
	process.Process
	data []byte
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func (p fileProcess) OpenMappingFile(*process.RawMapping) (process.ReadAtCloser, error) {
	return nopCloser{bytes.NewReader(p.data)}, nil
}

func TestReportExecutableClassifiesELF(t *testing.T) {
	self, err := os.ReadFile("/proc/self/exe")
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		data  []byte
		isELF bool
	}{
		// .NET assemblies are PE files, which start with "MZ".
		{name: "pe", data: []byte("MZ\x90\x00\x03\x00\x00\x00"), isELF: false},
		{name: "elf", data: self, isELF: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			execs, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](16, libpf.FileID.Hash32)
			require.NoError(t, err)
			tracker := &execTracker{executables: execs, disableSymbolUpload: true}

			fileID := libpf.NewFileID(1, 2)
			tracker.ReportExecutable(&reporter.ExecutableMetadata{
				MappingFile: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
					FileID:     fileID,
					FileName:   libpf.Intern(tc.name),
					GnuBuildID: "build-id",
				}),
				Process: fileProcess{data: tc.data},
				Mapping: &process.RawMapping{Path: "/" + tc.name},
			})

			info, ok := execs.Get(fileID)
			require.True(t, ok, "executable should be cached")
			require.Equal(t, tc.isELF, info.IsELF)
			require.Equal(t, tc.name, info.FileName)
			require.Equal(t, "build-id", info.BuildID)
		})
	}
}

// TestMetricsBridgeKnowsProfilerMetrics guards against the bridge drifting from
// the profiler library: ID 296 was added upstream and got logged as unknown on
// every flush while the agent kept its own copy of the definitions.
func TestMetricsBridgeKnowsProfilerMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	b := newMetricsBridge(reg)

	id := otelmetrics.MetricID(otelmetrics.IDUnwindNativeErrUnsupportedAnonymousMapping)
	require.Contains(t, b.defs, id)

	b.ReportMetrics(0, []uint32{uint32(id)}, []int64{3})
	b.ReportMetrics(0, []uint32{uint32(id)}, []int64{2})

	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, mfs, 1)
	require.Equal(t, "bpf_native_errors_unsupported_anonymous_mapping", mfs[0].GetName())
	require.InDelta(t, 5, mfs[0].GetMetric()[0].GetCounter().GetValue(), 0)
}
