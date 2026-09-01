package reporter

import (
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

func testExecutables(t *testing.T) *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo] {
	t.Helper()
	execs, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](128, libpf.FileID.Hash32)
	require.NoError(t, err)
	return execs
}

func testBuilder(t *testing.T) *pprofileBuilder {
	t.Helper()
	return newPprofileBuilder(testExecutables(t), "test-node")
}

// resolveAttrs turns a record's attribute indices into a plain map, which is
// how every assertion below reads the dictionary-encoded output.
func resolveAttrs(dict pprofile.ProfilesDictionary, indices pcommon.Int32Slice) map[string]string {
	out := make(map[string]string, indices.Len())
	for i := range indices.Len() {
		a := dict.AttributeTable().At(int(indices.At(i)))
		out[dict.StringTable().At(int(a.KeyStrindex()))] = a.Value().Str()
	}
	return out
}

func onlyProfile(t *testing.T, p pprofile.Profiles) pprofile.Profile {
	t.Helper()
	require.Equal(t, 1, p.ResourceProfiles().Len())
	sp := p.ResourceProfiles().At(0).ScopeProfiles()
	require.Equal(t, 1, sp.Len())
	require.Equal(t, 1, sp.At(0).Profiles().Len())
	return sp.At(0).Profiles().At(0)
}

// onlyLocation walks the single sample's single stack frame back to its
// Location, which is where frame type, address, and mapping live.
func onlyLocation(t *testing.T, p pprofile.Profiles) (pprofile.Location, pprofile.ProfilesDictionary) {
	t.Helper()
	dict := p.Dictionary()
	profile := onlyProfile(t, p)
	require.Equal(t, 1, profile.Samples().Len())
	stack := dict.StackTable().At(int(profile.Samples().At(0).StackIndex()))
	require.Equal(t, 1, stack.LocationIndices().Len())
	return dict.LocationTable().At(int(stack.LocationIndices().At(0))), dict
}

// newTestMapping interns a mapping the way the tracer would, so classifyFrame
// sees the same shape it does in production.
func newTestMapping(fileID libpf.FileID, fileName, gnuBuildID, goBuildID string) libpf.FrameMapping {
	return libpf.NewFrameMapping(libpf.FrameMappingData{
		File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
			FileID:     fileID,
			FileName:   libpf.Intern(fileName),
			GnuBuildID: gnuBuildID,
			GoBuildID:  goBuildID,
		}),
	})
}

func frame(t *testing.T, f libpf.Frame) libpf.Frames {
	t.Helper()
	var frames libpf.Frames
	frames.Append(&f)
	return frames
}

func addOne(b *pprofileBuilder, st sampleType, s sampleData) pprofile.Profiles {
	b.AddSample(resourceLabels{PID: 1000}, st, s)
	return b.Build(time.Unix(0, 0), time.Unix(5, 0))
}

// TestPprofileSampleTypes pins the origin-to-sample-type table. These strings
// are what a query selects on, so a silent rename breaks dashboards.
func TestPprofileSampleTypes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		st         sampleType
		wantType   string
		wantUnit   string
		wantPeriod int64
	}{
		{"cpu", cpuSampleType(19), "samples", "count", int64(1e9) / 19},
		{"offcpu", offCPUSampleType, "off_cpu", "nanoseconds", 0},
		{"probe", probeSampleType, "events", "count", 0},
		{"gpu kernel", gpuKernelSampleType, "gpu_kernel_time", "nanoseconds", 0},
		{"gpu pc", gpuPCSampleType(42), "gpu_pcsample", "count", 42},
		{"gpu merged", gpuMergedSampleType, "gpu_time", "nanoseconds", 0},
		{"inuse objects", memInuseObjects, "inuse_objects", "count", memorySamplePeriod},
		{"inuse space", memInuseSpace, "inuse_space", "bytes", memorySamplePeriod},
		{"alloc objects", memAllocObjects, "alloc_objects", "count", memorySamplePeriod},
		{"alloc space", memAllocSpace, "alloc_space", "bytes", memorySamplePeriod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testBuilder(t)
			out := addOne(b, tc.st, sampleData{
				Frames: frame(t, libpf.Frame{Type: libpf.NativeFrame}),
				Value:  1,
			})

			profile := onlyProfile(t, out)
			dict := out.Dictionary()
			require.Equal(t, tc.wantType, dict.StringTable().At(int(profile.SampleType().TypeStrindex())))
			require.Equal(t, tc.wantUnit, dict.StringTable().At(int(profile.SampleType().UnitStrindex())))
			require.Equal(t, tc.wantPeriod, profile.Period())
		})
	}
}

// TestPprofileNativeFrameBuildID is the symbolization contract: a native frame
// must carry a build ID the debuginfo pipeline can key an artifact on, and no
// function (those are resolved server-side).
func TestPprofileNativeFrameBuildID(t *testing.T) {
	execs := testExecutables(t)
	fileID := libpf.NewFileID(0x1122334455667788, 0x99aabbccddeeff00)
	execs.Add(fileID, metadata.ExecInfo{FileName: "/usr/bin/foo", BuildID: "abc123"})

	b := newPprofileBuilder(execs, "test-node")
	out := addOne(b, cpuSampleType(19), sampleData{
		Frames: frame(t, libpf.Frame{
			Type:            libpf.NativeFrame,
			AddressOrLineno: 0x4711,
			Mapping:         newTestMapping(fileID, "/usr/bin/foo", "abc123", ""),
		}),
		Value: 1,
	})

	loc, dict := onlyLocation(t, out)
	require.Equal(t, uint64(0x4711), loc.Address())
	require.Zero(t, loc.Lines().Len(),
		"native frames must not carry a function; the backend symbolizes them")

	locAttrs := resolveAttrs(dict, loc.AttributeIndices())
	require.Equal(t, "native", locAttrs[profileFrameTypeKey])

	mapping := dict.MappingTable().At(int(loc.MappingIndex()))
	require.Equal(t, "/usr/bin/foo", dict.StringTable().At(int(mapping.FilenameStrindex())))
	require.Equal(t, "abc123", resolveAttrs(dict, mapping.AttributeIndices())[attrBuildIDGNU])
}

// TestPprofileNativeFrameHtlhashFallback covers a binary with no GNU build ID.
// Both backends fall back to the FileID hash, and it must reach the wire under
// the htlhash key or those binaries symbolize nowhere.
func TestPprofileNativeFrameHtlhashFallback(t *testing.T) {
	execs := testExecutables(t)
	fileID := libpf.NewFileID(0xdeadbeefcafef00d, 0x0123456789abcdef)
	execs.Add(fileID, metadata.ExecInfo{FileName: "/opt/app/bin", BuildID: ""})

	b := newPprofileBuilder(execs, "test-node")
	out := addOne(b, cpuSampleType(19), sampleData{
		Frames: frame(t, libpf.Frame{
			Type:            libpf.NativeFrame,
			AddressOrLineno: 0x1000,
			Mapping:         newTestMapping(fileID, "/opt/app/bin", "", ""),
		}),
		Value: 1,
	})

	loc, dict := onlyLocation(t, out)
	mapping := dict.MappingTable().At(int(loc.MappingIndex()))
	attrs := resolveAttrs(dict, mapping.AttributeIndices())
	require.Empty(t, attrs[attrBuildIDGNU])
	require.Equal(t, fileID.StringNoQuotes(), attrs[attrBuildIDHtlhash],
		"a binary with no GNU build ID must fall back to the FileID hash")
}

// TestPprofileCUDAFrame asserts that the two values a symbolizer needs to
// resolve a GPU kernel -- the cubin CRC and the mangled kernel name -- both
// survive the encoding, and that the frame type gating that lookup is present.
func TestPprofileCUDAFrame(t *testing.T) {
	cubinID := libpf.NewFileID(0xaaaabbbbccccdddd, 0xeeeeffff00001111)

	b := testBuilder(t)
	out := addOne(b, gpuPCSampleType(64), sampleData{
		Frames: frame(t, libpf.Frame{
			Type:            libpf.CUDAPCFrame,
			AddressOrLineno: 0x80,
			FunctionName:    libpf.Intern("_Z6kernelPfi"),
			Mapping:         newTestMapping(cubinID, "app.cubin", "", ""),
		}),
		Value: 3,
	})

	loc, dict := onlyLocation(t, out)
	require.Equal(t, "cuda-pc", resolveAttrs(dict, loc.AttributeIndices())[profileFrameTypeKey])

	mapping := dict.MappingTable().At(int(loc.MappingIndex()))
	require.Equal(t, cubinID.StringNoQuotes(),
		resolveAttrs(dict, mapping.AttributeIndices())[attrBuildIDHtlhash],
		"the cubin CRC is half of the derived per-kernel artifact key")

	require.Equal(t, 1, loc.Lines().Len())
	fn := dict.FunctionTable().At(int(loc.Lines().At(0).FunctionIndex()))
	require.Equal(t, "_Z6kernelPfi", dict.StringTable().At(int(fn.SystemNameStrindex())),
		"the mangled kernel name is the other half of the key")
}

// TestPprofileMemoryFrame is the case upstream's converter gets wrong: the
// build ID and executable path ride on the frame rather than a mapping, so a
// generic classifier emits a function named after a build ID.
func TestPprofileMemoryFrame(t *testing.T) {
	b := testBuilder(t)
	out := addOne(b, memInuseSpace, sampleData{
		Frames: frame(t, libpf.Frame{
			Type:            libpf.NativeFrame,
			AddressOrLineno: 0x2000,
			FunctionName:    libpf.Intern("build-id-not-a-function"),
			SourceFile:      libpf.Intern("/usr/bin/leaky"),
		}),
		Value:                 4096,
		SyntheticMemoryFrames: true,
		MemoryBuildID:         "build-id-not-a-function",
		MemoryExecPath:        "/usr/bin/leaky",
	})

	loc, dict := onlyLocation(t, out)
	require.Zero(t, loc.Lines().Len(),
		"a memory frame's stashed build ID must not become a function name")

	mapping := dict.MappingTable().At(int(loc.MappingIndex()))
	require.Equal(t, "/usr/bin/leaky", dict.StringTable().At(int(mapping.FilenameStrindex())))
	require.Equal(t, "build-id-not-a-function",
		resolveAttrs(dict, mapping.AttributeIndices())[attrBuildIDGNU])
}

// TestPprofileInterpretedFrame checks the frames that never touch the debuginfo
// pipeline: they arrive symbolized and must carry their function and line.
func TestPprofileInterpretedFrame(t *testing.T) {
	b := testBuilder(t)
	out := addOne(b, cpuSampleType(19), sampleData{
		Frames: frame(t, libpf.Frame{
			Type:         libpf.PythonFrame,
			FunctionName: libpf.Intern("handler"),
			SourceFile:   libpf.Intern("app/views.py"),
			SourceLine:   42,
		}),
		Value: 1,
	})

	loc, dict := onlyLocation(t, out)
	require.Equal(t, 1, loc.Lines().Len())
	require.EqualValues(t, 42, loc.Lines().At(0).Line())
	fn := dict.FunctionTable().At(int(loc.Lines().At(0).FunctionIndex()))
	require.Equal(t, "handler", dict.StringTable().At(int(fn.SystemNameStrindex())))
	require.Equal(t, "app/views.py", dict.StringTable().At(int(fn.FilenameStrindex())))
}

// TestPprofileAttributeSplit is the assertion behind the resource/sample split:
// process-invariant labels belong on the Resource and must not repeat per
// sample.
func TestPprofileAttributeSplit(t *testing.T) {
	b := testBuilder(t)
	res := resourceLabels{
		Labels:         labels.FromStrings("node", "test-node", "namespace", "prod"),
		PID:            1000,
		ExecutablePath: "/usr/bin/foo",
		ContainerID:    "container-abc",
	}
	b.AddSample(res, cpuSampleType(19), sampleData{
		Frames:       frame(t, libpf.Frame{Type: libpf.NativeFrame}),
		Value:        1,
		SampleLabels: labels.FromStrings("cpu", "3", "thread_id", "77", "thread_name", "worker"),
		CustomLabels: map[libpf.String]libpf.String{libpf.Intern("tenant"): libpf.Intern("acme")},
	})
	out := b.Build(time.Unix(0, 0), time.Unix(5, 0))

	resAttrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()
	require.Equal(t, "test-node", resAttrs["node"])
	require.Equal(t, "prod", resAttrs["namespace"])
	require.Equal(t, "/usr/bin/foo", resAttrs[attrProcessExePath])
	require.Equal(t, "container-abc", resAttrs[attrContainerID])
	require.EqualValues(t, 1000, resAttrs[attrProcessPID])
	require.NotContains(t, resAttrs, "cpu", "per-sample labels must not be on the resource")

	dict := out.Dictionary()
	profile := onlyProfile(t, out)
	sampleAttrs := resolveAttrs(dict, profile.Samples().At(0).AttributeIndices())
	require.Equal(t, "3", sampleAttrs[attrCPUNumber])
	require.Equal(t, "77", sampleAttrs[attrThreadID])
	require.Equal(t, "worker", sampleAttrs[attrThreadName])
	require.Equal(t, "acme", sampleAttrs[attrProcessLabelPrefix+"tenant"])
	require.NotContains(t, sampleAttrs, "node",
		"node is constant per process and must not repeat on every sample")
}

// TestPprofileResourceReuse guards the thing that keeps a batch small: two
// samples from one process share one ResourceProfiles, and two sample types
// within it become two Profiles rather than two resources.
func TestPprofileResourceReuse(t *testing.T) {
	b := testBuilder(t)
	res := resourceLabels{Labels: labels.FromStrings("node", "test-node"), PID: 1000}
	frames := frame(t, libpf.Frame{Type: libpf.NativeFrame})

	b.AddSample(res, cpuSampleType(19), sampleData{Frames: frames, Value: 1})
	b.AddSample(res, cpuSampleType(19), sampleData{Frames: frames, Value: 1, Timestamp: 1})
	b.AddSample(res, offCPUSampleType, sampleData{Frames: frames, Value: 500})

	other := resourceLabels{Labels: labels.FromStrings("node", "test-node"), PID: 2000}
	b.AddSample(other, cpuSampleType(19), sampleData{Frames: frames, Value: 1})

	out := b.Build(time.Unix(0, 0), time.Unix(5, 0))
	require.Equal(t, 2, out.ResourceProfiles().Len(), "one resource per process")

	first := out.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles()
	require.Equal(t, 2, first.Len(), "two sample types become two profiles, not two resources")
	require.Equal(t, 1, out.Dictionary().StackTable().Len(), "the shared stack interns once")
}

// TestPprofileBuildStampsWindow asserts every profile carries the collection
// window, and that Build leaves the builder empty for the next interval.
func TestPprofileBuildStampsWindow(t *testing.T) {
	b := testBuilder(t)
	b.AddSample(resourceLabels{PID: 1}, cpuSampleType(19), sampleData{
		Frames: frame(t, libpf.Frame{Type: libpf.NativeFrame}),
		Value:  1,
	})
	require.Equal(t, 1, b.SampleCount())

	start, end := time.Unix(100, 0), time.Unix(105, 0)
	out := b.Build(start, end)

	profile := onlyProfile(t, out)
	require.EqualValues(t, start.UnixNano(), profile.Time())
	require.EqualValues(t, 5*time.Second, profile.DurationNano())

	require.Zero(t, b.SampleCount(), "Build must reset the builder")
	require.Zero(t, b.Build(start, end).ResourceProfiles().Len())
}
