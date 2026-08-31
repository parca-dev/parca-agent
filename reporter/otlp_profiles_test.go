package reporter

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/flags"
)

// fakeProfilesServer captures whatever the agent exports, so a test can assert
// on the bytes that actually crossed a gRPC connection rather than on the
// builder's in-memory output.
type fakeProfilesServer struct {
	pprofileotlp.UnimplementedGRPCServer

	mu       sync.Mutex
	received []pprofile.Profiles
}

func (s *fakeProfilesServer) Export(_ context.Context, req pprofileotlp.ExportRequest) (pprofileotlp.ExportResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The request's backing data is reused after Export returns, so copy.
	cp := pprofile.NewProfiles()
	req.Profiles().CopyTo(cp)
	s.received = append(s.received, cp)
	return pprofileotlp.NewExportResponse(), nil
}

func (s *fakeProfilesServer) batches() []pprofile.Profiles {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]pprofile.Profiles(nil), s.received...)
}

// startFakeCollector runs an in-process OTLP profiles receiver and returns a
// client connection to it.
func startFakeCollector(t *testing.T) (*fakeProfilesServer, *grpc.ClientConn) {
	t.Helper()

	// The vtproto codec globally replaces gRPC's "proto" codec, and
	// pprofileotlp marshals only through its pdata branch. Without this the
	// export fails with an opaque marshal error, so registering it here is
	// also the regression guard for that ordering hazard.
	flags.RegisterProtoCodec()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	fake := &fakeProfilesServer{}
	pprofileotlp.RegisterGRPCServer(srv, fake)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return fake, conn
}

func newTestOTLPReporter(t *testing.T, conn *grpc.ClientConn) *otlpProfilesReporter {
	t.Helper()

	rep, err := NewOTLPProfiles(Config{
		CacheSize:           1024,
		LabelTTL:            10 * time.Minute,
		NodeName:            "test-node",
		AgentRevision:       "test",
		Registerer:          prometheus.NewRegistry(),
		SamplesPerSecond:    19,
		DisableSymbolUpload: true,
		ReportInterval:      time.Hour, // flushes are driven manually
	}, conn)
	require.NoError(t, err)

	return rep.(*otlpProfilesReporter)
}

// TestOTLPReporterSatisfiesParcaReporter is a compile-time contract check with a
// runtime assertion, so adding a method to ParcaReporter cannot leave this
// backend silently behind.
func TestOTLPReporterSatisfiesParcaReporter(t *testing.T) {
	_, conn := startFakeCollector(t)
	var rep ParcaReporter = newTestOTLPReporter(t, conn)
	require.NotNil(t, rep)
	require.NotNil(t, rep.Logger("test"), "Logger must fall back to a no-op, not nil")
	require.NotNil(t, rep.Tracer("test"), "Tracer must fall back to a no-op, not panic")
}

// TestOTLPReporterExportsOverGRPC is the end-to-end check: a trace event in,
// an OTLP profile with the expected sample type out, across a real connection.
func TestOTLPReporterExportsOverGRPC(t *testing.T) {
	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)

	trace := &libpf.Trace{}
	trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x1234})

	require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
		Origin:    support.TraceOriginSampling,
		Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID:       1000,
		TID:       1001,
		Comm:      libpf.NewCommFromString("worker"),
		CPU:       2,
	}))

	rep.windowStart = time.Now().Add(-5 * time.Second)
	require.NoError(t, rep.flush(context.Background()))

	batches := fake.batches()
	require.Len(t, batches, 1, "one flush must produce one export request")

	out := batches[0]
	dict := out.Dictionary()
	profile := onlyProfile(t, out)
	require.Equal(t, "samples", dict.StringTable().At(int(profile.SampleType().TypeStrindex())))
	require.Equal(t, 1, profile.Samples().Len())
	require.NotZero(t, profile.DurationNano(), "the collection window must be stamped")

	resAttrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()
	require.Equal(t, "test-node", resAttrs["node"])
}

// TestOTLPReporterEveryOriginIsExportable is the assertion that motivated
// writing our own converter: upstream's rejects the CUDA and GPU-PC origins
// before encoding, so those samples would vanish.
func TestOTLPReporterEveryOriginIsExportable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		origin   libpf.Origin
		wantType string
	}{
		{"sampling", support.TraceOriginSampling, "samples"},
		{"offcpu", support.TraceOriginOffCPU, "off_cpu"},
		{"probe", support.TraceOriginProbe, "events"},
		{"cuda", support.TraceOriginCuda, "gpu_kernel_time"},
		{"gpu pc", support.TraceOriginGpuPC, "gpu_pcsample"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, conn := startFakeCollector(t)
			rep := newTestOTLPReporter(t, conn)

			trace := &libpf.Trace{}
			trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x10})

			require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
				Origin:    tc.origin,
				Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
				PID:       1000,
				Value:     7,
			}))
			require.NoError(t, rep.flush(context.Background()))

			batches := fake.batches()
			require.Len(t, batches, 1, "origin %s produced no export", tc.name)
			out := batches[0]
			profile := onlyProfile(t, out)
			require.Equal(t, tc.wantType,
				out.Dictionary().StringTable().At(int(profile.SampleType().TypeStrindex())))
		})
	}
}

// TestOTLPReporterEmptyBatchSkipsExport keeps an idle agent from sending empty
// requests every interval.
func TestOTLPReporterEmptyBatchSkipsExport(t *testing.T) {
	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)

	require.NoError(t, rep.flush(context.Background()))
	require.Empty(t, fake.batches(), "an empty batch must not be exported")
}

// TestOTLPReporterMemoryTracesExportFourTypes is the structural reason this
// backend cannot delegate to upstream's converter: one oomprof sample becomes
// four sample types, and pprofile.Profile carries exactly one each.
func TestOTLPReporterMemoryTracesExportFourTypes(t *testing.T) {
	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)
	rep.reportAllocs = true

	require.NoError(t, rep.ReportMemoryTraces(
		[]oomprof.Sample{{
			Addresses:  []oomprof.Address{0x1000, 0x2000},
			Allocs:     10,
			Frees:      4,
			AllocBytes: 8192,
			FreeBytes:  2048,
		}},
		oomprof.SampleMeta{
			PID:            1000,
			Comm:           "leaky",
			ProcessName:    "leaky",
			ExecutablePath: "/usr/bin/leaky",
			BuildID:        "test-build-id",
			Timestamp:      uint64(time.Now().UnixNano()),
		},
	))
	require.NoError(t, rep.flush(context.Background()))

	batches := fake.batches()
	require.Len(t, batches, 1)
	out := batches[0]
	dict := out.Dictionary()

	require.Equal(t, 1, out.ResourceProfiles().Len(), "one process, one resource")
	profiles := out.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles()

	got := make(map[string]bool, profiles.Len())
	for i := range profiles.Len() {
		got[dict.StringTable().At(int(profiles.At(i).SampleType().TypeStrindex()))] = true
	}
	for _, want := range []string{"inuse_objects", "inuse_space", "alloc_objects", "alloc_space"} {
		require.True(t, got[want], "missing memory sample type %s", want)
	}

	// And the build ID must be a mapping attribute, never a function name.
	stack := dict.StackTable().At(int(profiles.At(0).Samples().At(0).StackIndex()))
	loc := dict.LocationTable().At(int(stack.LocationIndices().At(0)))
	require.Zero(t, loc.Lines().Len())
	mapping := dict.MappingTable().At(int(loc.MappingIndex()))
	require.Equal(t, "/usr/bin/leaky", dict.StringTable().At(int(mapping.FilenameStrindex())))
	require.Equal(t, "test-build-id",
		resolveAttrs(dict, mapping.AttributeIndices())[attrBuildIDGNU])
}
