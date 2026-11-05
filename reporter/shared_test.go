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
	"context"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"

	debuginfopb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/debuginfo/v1alpha1"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
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

func (p fileProcess) OpenMappingFile(*process.RawMapping) (fs.File, error) {
	// fstest's files implement io.ReaderAt, as real mapping files do.
	return fstest.MapFS{"f": {Data: p.data}}.Open("f")
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

// Exercise ReportExecutable through upload negotiation and each profile encoding,
// rather than testing the selector independently of its callers.
func TestExecutableBuildIDAcrossExports(t *testing.T) {
	self, err := os.ReadFile("/proc/self/exe")
	require.NoError(t, err)
	fileID := libpf.NewFileID(0x1122334455667788, 0x99aabbccddeeff00)
	const hash = "112233445566778899aabbccddeeff00"
	const goID = "actionID/contentID/otherActionID/otherContentID"
	for _, tc := range []struct {
		name, gnuID, goID, want string
		wantType                debuginfopb.BuildIDType
	}{
		{"gnu over go and hash", "abc123", goID, "abc123", debuginfopb.BuildIDType_BUILD_ID_TYPE_GNU},
		{"go over hash", "", goID, goID, debuginfopb.BuildIDType_BUILD_ID_TYPE_GO},
		{"hash only", "", "", hash, debuginfopb.BuildIDType_BUILD_ID_TYPE_HASH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var checks []*debuginfopb.ShouldInitiateUploadRequest
				var uploads []*debuginfopb.InitiateUploadRequest
				u, _ := startSymbolUploader(t, &symbolUploadClient{
					should: func(req *debuginfopb.ShouldInitiateUploadRequest) *debuginfopb.ShouldInitiateUploadResponse {
						checks = append(checks, req)
						if len(checks) == 1 {
							return &debuginfopb.ShouldInitiateUploadResponse{RetryRequired: true}
						}
						return &debuginfopb.ShouldInitiateUploadResponse{ShouldInitiateUpload: true}
					},
					initiate: func(req *debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
						uploads = append(uploads, req)
						return &debuginfopb.InitiateUploadResponse{}, nil
					},
				}, nil)
				execs := testExecutables(t)
				tracker := &execTracker{executables: execs, uploader: u}
				mapping := newTestMapping(fileID, "/opt/app/bin", tc.gnuID, tc.goID)
				args := &reporter.ExecutableMetadata{
					MappingFile: mapping.Value().File,
					Process:     fileProcess{data: self},
				}
				tracker.ReportExecutable(args)
				synctest.Wait()
				// Cached executable reports must not change identity or bypass cooldown.
				tracker.ReportExecutable(args)
				time.Sleep(5 * time.Minute)
				synctest.Wait()
				require.Len(t, checks, 2)
				for _, req := range checks {
					require.Equal(t, tc.want, req.BuildId)
					require.Equal(t, tc.wantType, req.BuildIdType)
				}
				require.Len(t, uploads, 1)
				require.Equal(t, tc.want, uploads[0].BuildId)
				require.Equal(t, tc.wantType, uploads[0].BuildIdType)
				require.Equal(t, hash, uploads[0].Hash, "content hash remains independent of the selected ID")

				info, ok := execs.Get(fileID)
				require.True(t, ok)
				require.Equal(t, tc.want, info.BuildID)
				f := libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x4711, Mapping: mapping}
				frames := frame(t, f)
				traceHash := libpf.NewTraceHash(1, 2)
				stacks, err := lru.NewSynced[libpf.TraceHash, libpf.Frames](16, libpf.TraceHash.Hash32)
				require.NoError(t, err)
				stacks.Add(traceHash, frames)
				r := &arrowReporter{executables: execs, stacks: stacks, mem: memory.DefaultAllocator}

				// Arrow v1 resolves requested stacktraces in a separate record.
				ids := array.NewBinaryBuilder(memory.DefaultAllocator, arrow.BinaryTypes.Binary)
				defer ids.Release()
				ids.Append(traceHash.Bytes())
				idArray := ids.NewBinaryArray()
				defer idArray.Release()
				v1, err := r.buildStacktraceRecord(context.Background(), idArray)
				require.NoError(t, err)
				defer v1.Release()
				locations := v1.Column(v1.Schema().FieldIndices("locations")[0]).(*array.List).ListValues().(*array.Struct)
				idx, ok := locations.DataType().(*arrow.StructType).FieldIdx("mapping_build_id")
				require.True(t, ok)
				ree := locations.Field(idx).(*array.RunEndEncoded)
				dict := ree.Values().(*array.Dictionary)
				require.Equal(t, tc.want, string(dict.Dictionary().(*array.Binary).Value(dict.GetValueIndex(ree.GetPhysicalIndex(0)))))

				// Arrow v2 carries the same ID in its inline location dictionary.
				r.sampleWriterV2 = NewSampleWriterV2(memory.DefaultAllocator)
				defer r.sampleWriterV2.Release()
				r.sampleWriterV2.Stacktrace.AppendStacktrace(traceHash, frames, r.appendLocationV2)
				v2 := r.sampleWriterV2.Stacktrace.NewArray().(*array.ListView)
				defer v2.Release()
				locations = v2.ListValues().(*array.Dictionary).Dictionary().(*array.Struct)
				idx, ok = locations.DataType().(*arrow.StructType).FieldIdx("mapping_build_id")
				require.True(t, ok)
				require.Equal(t, tc.want, dictString(locations.Field(idx), 0))

				// OTLP retains typed IDs and the historical hash when GNU is absent.
				out := addOne(newPprofileBuilder(execs, "test-node", false, nil), cpuSampleType(19), sampleData{Frames: frames, Value: 1})
				loc, profileDict := onlyLocation(t, out)
				attrs := resolveAttrs(profileDict, profileDict.MappingTable().At(int(loc.MappingIndex())).AttributeIndices())
				require.Equal(t, tc.gnuID, attrs[attrBuildIDGNU])
				require.Equal(t, tc.goID, attrs[attrBuildIDGo], "preserve the full slash-separated Go ID")
				if tc.gnuID == "" {
					require.Equal(t, hash, attrs[attrBuildIDHtlhash])
				} else {
					require.NotContains(t, attrs, attrBuildIDHtlhash)
				}
				var effective string
				for _, key := range []string{attrBuildIDGNU, attrBuildIDGo, attrBuildIDHtlhash} {
					if attrs[key] != "" {
						effective = attrs[key]
						break
					}
				}
				require.Equal(t, tc.want, effective)
			})
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
