package reporter

import (
	"context"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/parca-dev/oomprof/oomprof"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/otel/attribute"
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
		ExternalLabels:      []Label{{Name: "parca.agent", Value: "true"}},
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
	require.NotNil(t, rep.LoggerProvider(), "LoggerProvider must fall back to a no-op, not nil")
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
		ProfileType: testProfileTypeSampling,
		Timestamp:   libpf.UnixTime64(time.Now().UnixNano()),
		PID:         1000,
		TID:         1001,
		Comm:        libpf.NewCommFromString("worker"),
		CPU:         2,
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
	require.Zero(t, profile.Samples().At(0).LinkIndex())
	require.Equal(t, 1, dict.LinkTable().Len(), "no context means only the reserved link")
	require.NotZero(t, profile.DurationNano(), "the collection window must be stamped")

	resAttrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()
	require.Equal(t, "test-node", resAttrs[attrHostName])
	require.Equal(t, "true", resAttrs["parca.agent"])
	require.NotContains(t, resAttrs, "node", "host.name carries the node name")
}

func TestOTLPReporterTraceLinks(t *testing.T) {
	const traceHex = "00112233445566778899aabbccddeeff"
	const spanHex = "1020304050607080"
	traceID := libpf.TraceID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	spanID := libpf.SpanID{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	otherTrace := libpf.TraceID{1}
	otherSpan := libpf.SpanID{2}
	cases := []struct {
		name                  string
		traceLabel, spanLabel string
		metaTrace             libpf.TraceID
		metaSpan              libpf.SpanID
		wantTrace             libpf.TraceID
		wantSpan              libpf.SpanID
	}{
		{name: "custom labels", traceLabel: traceHex, spanLabel: spanHex, wantTrace: traceID, wantSpan: spanID},
		{name: "same link", traceLabel: traceHex, spanLabel: spanHex, wantTrace: traceID, wantSpan: spanID},
		{name: "different span", traceLabel: traceHex, spanLabel: "0200000000000000", wantTrace: traceID, wantSpan: otherSpan},
		{name: "different trace", traceLabel: "01000000000000000000000000000000", spanLabel: spanHex, wantTrace: otherTrace, wantSpan: spanID},
		{name: "missing both"},
		{name: "missing span", traceLabel: traceHex},
		{name: "missing trace", spanLabel: spanHex},
		{name: "short trace", traceLabel: traceHex[2:], spanLabel: spanHex},
		{name: "long trace", traceLabel: traceHex + "00", spanLabel: spanHex},
		{name: "nonhex trace", traceLabel: "g0112233445566778899aabbccddeeff", spanLabel: spanHex},
		{name: "zero trace", traceLabel: "00000000000000000000000000000000", spanLabel: spanHex},
		{name: "short span", traceLabel: traceHex, spanLabel: spanHex[2:]},
		{name: "long span", traceLabel: traceHex, spanLabel: spanHex + "00"},
		{name: "nonhex span", traceLabel: traceHex, spanLabel: "g020304050607080"},
		{name: "zero span", traceLabel: traceHex, spanLabel: "0000000000000000"},
		{name: "metadata", metaTrace: otherTrace, metaSpan: otherSpan, wantTrace: otherTrace, wantSpan: otherSpan},
		{name: "metadata wins", traceLabel: traceHex, spanLabel: spanHex, metaTrace: otherTrace, metaSpan: otherSpan, wantTrace: otherTrace, wantSpan: otherSpan},
		{name: "complete label fallback", traceLabel: traceHex, spanLabel: spanHex, metaTrace: otherTrace, wantTrace: traceID, wantSpan: spanID},
		{name: "do not mix metadata trace with label span", spanLabel: spanHex, metaTrace: otherTrace},
		{name: "do not mix metadata span with label trace", traceLabel: traceHex, metaSpan: otherSpan},
	}

	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)
	// Reverse arrival order in the next batch so stale dictionary indices
	// cannot accidentally resolve to the same IDs after a flush.
	for batch := range 2 {
		for j := range cases {
			i := j
			if batch == 1 {
				i = len(cases) - 1 - j
			}
			tc := cases[i]
			trace := &libpf.Trace{CustomLabels: map[libpf.String]libpf.String{
				libpf.Intern("tenant"): libpf.Intern("acme"),
			}}
			if tc.traceLabel != "" {
				trace.CustomLabels[libpf.Intern("otel.trace_id")] = libpf.Intern(tc.traceLabel)
			}
			if tc.spanLabel != "" {
				trace.CustomLabels[libpf.Intern("otel.span_id")] = libpf.Intern(tc.spanLabel)
			}
			trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x1234})
			meta := &samples.TraceEventMeta{
				ProfileType: testProfileTypeSampling, Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
				PID: 1000, TID: 1001, TraceID: tc.metaTrace, SpanID: tc.metaSpan,
			}
			require.NoError(t, rep.ReportTraceEvent(trace, meta), tc.name)
			require.Equal(t, tc.metaTrace, meta.TraceID, "must not mutate caller metadata")
			require.Equal(t, tc.metaSpan, meta.SpanID, "must not mutate caller metadata")
		}
		require.NoError(t, rep.flush(context.Background()))
		out := fake.batches()[batch]
		requireConformant(t, out)
		dict := out.Dictionary()
		require.Equal(t, 5, dict.LinkTable().Len(), "four distinct pairs plus the reserved link")
		profile := onlyProfile(t, out)
		require.Equal(t, len(cases), profile.Samples().Len())
		for j := range cases {
			i := j
			if batch == 1 {
				i = len(cases) - 1 - j
			}
			tc := cases[i]
			sample := profile.Samples().At(j)
			if tc.wantTrace == (libpf.TraceID{}) {
				require.Zero(t, sample.LinkIndex(), tc.name)
			} else {
				require.Positive(t, sample.LinkIndex(), tc.name)
				link := dict.LinkTable().At(int(sample.LinkIndex()))
				require.Equal(t, pcommon.TraceID(tc.wantTrace), link.TraceID(), tc.name)
				require.Equal(t, pcommon.SpanID(tc.wantSpan), link.SpanID(), tc.name)
			}
			attrs := resolveAttrs(dict, sample.AttributeIndices())
			require.Equal(t, "acme", attrs[attrProcessLabelPrefix+"tenant"])
			require.Equal(t, tc.traceLabel, attrs[attrProcessLabelPrefix+"otel.trace_id"])
			require.Equal(t, tc.spanLabel, attrs[attrProcessLabelPrefix+"otel.span_id"])
		}
	}
}

func TestOTLPReporterLocalDiscovery(t *testing.T) {
	// Running in Kubernetes must not require a service-account token or any
	// reachable API/runtime endpoint in local mode.
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "1")
	t.Setenv("DOCKER_HOST", "/nonexistent/docker.sock")
	fake, conn := startFakeCollector(t)
	reporter, err := NewOTLPProfiles(Config{
		CacheSize: 16, LabelTTL: time.Minute, NodeName: "test-node",
		LocalMetadataOnly: true, DisableSymbolUpload: true,
		Registerer: prometheus.NewRegistry(), SamplesPerSecond: 19,
		ExternalLabels: []Label{
			{Name: "parca.agent", Value: "true"},
			{Name: "service.name", Value: "profiler"},
			{Name: "host.name", Value: "profiler-host"},
			{Name: "process.pid", Value: "9"},
		},
	}, conn)
	require.NoError(t, err)
	rep := reporter.(*otlpProfilesReporter)

	trace := &libpf.Trace{CustomLabels: map[libpf.String]libpf.String{
		libpf.Intern("tenant"): libpf.Intern("acme"),
	}}
	trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x1234})
	// The process has exited before export; retain the ID captured by the
	// profiler even when procfs can no longer supply one.
	pid := libpf.PID(1 << 30)
	meta := &samples.TraceEventMeta{
		ProfileType: testProfileTypeSampling, Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID: pid, TID: pid + 1, CPU: 3, Comm: libpf.NewCommFromString("worker-a"),
		ExecutablePath: libpf.Intern("/usr/bin/worker"), ContainerID: libpf.Intern("profiler-container-id"),
		ResourceAttrs: attribute.NewSet(attribute.String("service.name", "declared-service")),
	}
	require.NoError(t, rep.ReportTraceEvent(trace, meta))
	meta.TID, meta.CPU, meta.Comm = pid+2, 7, libpf.NewCommFromString("worker-b")
	trace.CustomLabels[libpf.Intern("tenant")] = libpf.Intern("northwind")
	require.NoError(t, rep.ReportTraceEvent(trace, meta))
	require.NoError(t, rep.flush(context.Background()))
	batches := fake.batches()
	require.Len(t, batches, 1)
	out := batches[0]
	attrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()
	require.Equal(t, "profiler-container-id", attrs["container.id"])
	require.Equal(t, "declared-service", attrs["service.name"])
	require.Equal(t, "true", attrs["parca.agent"])
	require.Equal(t, int64(pid), attrs["process.pid"])
	require.Equal(t, "/usr/bin/worker", attrs["process.executable.path"])
	require.Equal(t, "test-node", attrs["host.name"])
	require.Equal(t, runtime.GOARCH, attrs["host.arch"])
	require.Equal(t, "linux", attrs["os.type"])
	require.NotEmpty(t, attrs["os.version"])
	require.NotContains(t, attrs, "k8s.pod.name")
	require.NotContains(t, attrs, "process.command_line")
	for _, key := range []string{"cpu.logical_number", "thread.id", "thread.name", "process.context.label.tenant"} {
		require.NotContains(t, attrs, key, "per-sample data must not fragment resources")
	}
	profile := onlyProfile(t, out)
	require.Equal(t, 2, profile.Samples().Len(), "different threads and custom labels share one resource")
	for i, want := range []map[string]any{
		{"cpu.logical_number": int64(3), "thread.id": int64(pid + 1), "thread.name": "worker-a", "process.context.label.tenant": "acme"},
		{"cpu.logical_number": int64(7), "thread.id": int64(pid + 2), "thread.name": "worker-b", "process.context.label.tenant": "northwind"},
	} {
		sampleAttrs := map[string]any{}
		indices := profile.Samples().At(i).AttributeIndices()
		for j := range indices.Len() {
			a := out.Dictionary().AttributeTable().At(int(indices.At(j)))
			sampleAttrs[out.Dictionary().StringTable().At(int(a.KeyStrindex()))] = a.Value().AsRaw()
		}
		require.Equal(t, want, sampleAttrs, "sample attributes and types on the wire")
	}

	// Forks used by GPU resources retain the local providers and semconv
	// defaults, without initializing discovery clients again.
	fork, err := rep.ProcessLabels().Fork()
	require.NoError(t, err)
	resolved := fork.Resolve(context.Background(), libpf.PID(os.Getpid()), nil)
	require.True(t, resolved.Keep)
	require.Equal(t, runtime.GOARCH, resolved.Labels.Get("host.arch"))
}

// Attribution follows upstream's resolved resource and latest-snapshot policy,
// not the sampled thread name or an independent environment fallback.
func TestOTLPReporterProcessAttribution(t *testing.T) {
	accountant := attribute.NewSet(attribute.String("service.name", "accountant"))
	versionOnly := attribute.NewSet(attribute.String("service.version", "2"))
	env := map[libpf.String]libpf.String{
		libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("must-not-refill"),
		libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("service.name=also-wrong,service.namespace=env-only"),
	}
	for _, tc := range []struct {
		name      string
		snapshots []attribute.Set
		env       map[libpf.String]libpf.String
		want      map[string]any
	}{
		{"unnamed workers", []attribute.Set{{}, {}}, nil, map[string]any{}},
		{"declared service", []attribute.Set{accountant, accountant}, env, map[string]any{"service.name": "accountant"}},
		{"context without service name", []attribute.Set{versionOnly, versionOnly}, env, map[string]any{"service.version": "2"}},
		{"explicit empty service name", []attribute.Set{attribute.NewSet(attribute.String("service.name", ""))}, env, map[string]any{"service.name": ""}},
		{"late context", []attribute.Set{{}, accountant}, nil, map[string]any{"service.name": "accountant"}},
		{"changed context", []attribute.Set{accountant, versionOnly}, nil, map[string]any{"service.version": "2"}},
		{"cleared context", []attribute.Set{accountant, {}}, nil, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, conn := startFakeCollector(t)
			rep := newTestOTLPReporter(t, conn)
			trace := &libpf.Trace{}
			trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x1234})
			threads := []string{"G1 Refine#0", "C2 CompilerThre"}
			for i, snapshot := range tc.snapshots {
				require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
					ProfileType: testProfileTypeSampling, Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
					PID: 1 << 30, TID: libpf.PID(100 + i), Comm: libpf.NewCommFromString(threads[i]), CPU: uint32(3 + i),
					ExecutablePath: libpf.Intern("/usr/lib/jvm/bin/java"), ContainerID: libpf.Intern("container-a"),
					ResourceAttrs: snapshot,
					// The profiler already resolved this. Even an empty context
					// must not be refilled from the raw environment by the exporter.
					EnvVars: tc.env,
				}))
			}
			require.NoError(t, rep.flush(context.Background()))
			batches := fake.batches()
			require.Len(t, batches, 1)
			out := batches[0]
			require.Equal(t, 1, out.ResourceProfiles().Len(), "one process must not split by thread or resource snapshot")
			attrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()
			for _, key := range []string{"service.name", "service.version"} {
				if want, ok := tc.want[key]; ok {
					require.Equal(t, want, attrs[key])
				} else {
					require.NotContains(t, attrs, key)
				}
			}
			require.NotContains(t, attrs, "service.namespace", "resolved context is complete, not merged with env")
			require.Equal(t, "java", attrs["process.executable.name"], "executable identity is not thread comm")
			require.Equal(t, "/usr/lib/jvm/bin/java", attrs["process.executable.path"])
			require.Equal(t, int64(1<<30), attrs["process.pid"])
			require.Equal(t, "container-a", attrs["container.id"])
			profile := onlyProfile(t, out)
			require.Equal(t, len(tc.snapshots), profile.Samples().Len())
			for i := range profile.Samples().Len() {
				got := map[string]any{}
				indices := profile.Samples().At(i).AttributeIndices()
				for j := range indices.Len() {
					a := out.Dictionary().AttributeTable().At(int(indices.At(j)))
					got[out.Dictionary().StringTable().At(int(a.KeyStrindex()))] = a.Value().AsRaw()
				}
				require.Equal(t, map[string]any{
					"thread.name": threads[i], "thread.id": int64(100 + i), "cpu.logical_number": int64(3 + i),
				}, got)
				require.Equal(t, []int64{1}, profile.Samples().At(i).Values().AsRaw())
			}
			requireConformant(t, out)
		})
	}
}

// TestOTLPReporterEveryProfileTypeIsExportable is the assertion that motivated
// writing our own converter: upstream's rejects the CUDA and GPU-PC profile
// types before encoding, so those samples would vanish.
func TestOTLPReporterEveryProfileTypeIsExportable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		profileType *samples.TypeMetadata
		wantType    string
	}{
		{"sampling", testProfileTypeSampling, "samples"},
		{"offcpu", testProfileTypeOffCPU, "off_cpu"},
		{"probe", testProfileTypeProbe, "events"},
		{"cuda", gpu.ProfileTypeCuda, "gpu_kernel_time"},
		{"gpu pc", gpu.ProfileTypeGpuPC, "gpu_pcsample"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, conn := startFakeCollector(t)
			rep := newTestOTLPReporter(t, conn)

			trace := &libpf.Trace{CustomLabels: map[libpf.String]libpf.String{
				libpf.Intern("otel.trace_id"): libpf.Intern("01000000000000000000000000000000"),
				libpf.Intern("otel.span_id"):  libpf.Intern("0200000000000000"),
			}}
			trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x10})

			require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
				ProfileType:    tc.profileType,
				Timestamp:      libpf.UnixTime64(time.Now().UnixNano()),
				PID:            1000,
				Comm:           libpf.NewCommFromString("worker"),
				ExecutablePath: libpf.Intern("/usr/bin/java"),
				ContextValues:  []uint64{7},
			}))
			require.NoError(t, rep.flush(context.Background()))

			batches := fake.batches()
			require.Len(t, batches, 1, "profile type %s produced no export", tc.name)
			out := batches[0]
			profile := onlyProfile(t, out)
			require.Equal(t, tc.wantType,
				out.Dictionary().StringTable().At(int(profile.SampleType().TypeStrindex())))
			require.Equal(t, 1, profile.Samples().Len())
			require.Positive(t, profile.Samples().At(0).LinkIndex())
			link := out.Dictionary().LinkTable().At(int(profile.Samples().At(0).LinkIndex()))
			require.Equal(t, pcommon.TraceID{1}, link.TraceID())
			require.Equal(t, pcommon.SpanID{2}, link.SpanID())
			attrs := out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()
			require.NotContains(t, attrs, "service.name")
			require.Equal(t, "java", attrs["process.executable.name"])
			requireConformant(t, out)
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
	require.Equal(t, "true", out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()["parca.agent"])
	require.NotContains(t, out.ResourceProfiles().At(0).Resource().Attributes().AsRaw(), "service.name")
	require.Equal(t, "leaky", out.ResourceProfiles().At(0).Resource().Attributes().AsRaw()["process.executable.name"])
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

// TestOTLPReporterSelfDescribingProfileType covers origins such as the heap
// probe, whose TypeMetadata declares several sample types and their values:
// each sample type becomes its own profile, valued by AppendValues.
func TestOTLPReporterSelfDescribingProfileType(t *testing.T) {
	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)

	heapAlloc := &samples.TypeMetadata{
		SampleTypes: []samples.SampleType{
			{Type: "alloc_space", Unit: "bytes"},
			{Type: "alloc_objects", Unit: "count"},
		},
		ReportValues: true,
		AppendValues: func(dst []int64, meta *samples.TraceEventMeta) []int64 {
			return append(dst, int64(meta.ContextValues[0]), int64(meta.ContextValues[1]))
		},
	}

	trace := &libpf.Trace{}
	trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x10})
	require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
		ProfileType:   heapAlloc,
		Timestamp:     libpf.UnixTime64(time.Now().UnixNano()),
		PID:           1000,
		ContextValues: []uint64{4096, 3},
	}))
	require.NoError(t, rep.flush(context.Background()))

	batches := fake.batches()
	require.Len(t, batches, 1)
	require.Equal(t, map[string]int64{"alloc_space": 4096, "alloc_objects": 3},
		valuesByType(batches[0]))
}

// TestOTLPReporterMemoryTracesPeriod pins the period every memory profile
// carries: the Go heap sampling rate, in bytes of space.
func TestOTLPReporterMemoryTracesPeriod(t *testing.T) {
	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)

	require.NoError(t, rep.ReportMemoryTraces(
		[]oomprof.Sample{{Addresses: []oomprof.Address{0x1000}, Allocs: 10, Frees: 4, AllocBytes: 8192, FreeBytes: 2048}},
		oomprof.SampleMeta{PID: 1000, Comm: "leaky", ExecutablePath: "/usr/bin/leaky", Timestamp: uint64(time.Now().UnixNano())},
	))
	require.NoError(t, rep.flush(context.Background()))

	out := fake.batches()[0]
	require.Equal(t, map[string]int64{"inuse_space": 6144, "inuse_objects": 6}, valuesByType(out))
	dict := out.Dictionary()
	profiles := out.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles()
	for i := range profiles.Len() {
		p := profiles.At(i)
		require.Equal(t, "space", dict.StringTable().At(int(p.PeriodType().TypeStrindex())))
		require.Equal(t, "bytes", dict.StringTable().At(int(p.PeriodType().UnitStrindex())))
		require.Equal(t, memorySamplePeriod, p.Period())
	}
}

// TestOOMProfOTLPSinkExportsImmediately covers the supervising parent, which
// has no flush loop: each oomprof batch must reach the collector before
// SampleEvents returns.
func TestOOMProfOTLPSinkExportsImmediately(t *testing.T) {
	fake, conn := startFakeCollector(t)
	sink, err := NewOOMProfOTLPSink(conn, "test-node", map[string]string{"parca.agent": "true"}, true)
	require.NoError(t, err)

	require.False(t, sink.WaitForProfile(1000, 0, 0))
	require.NoError(t, sink.SampleEvents(
		[]oomprof.Sample{{Addresses: []oomprof.Address{0x1000}, Allocs: 10, Frees: 4, AllocBytes: 8192, FreeBytes: 2048}},
		oomprof.SampleMeta{PID: 1000, Comm: "worker", ProcessName: "custom-name", ExecutablePath: "/parca-agent", BuildID: "test-build-id", Timestamp: uint64(time.Now().UnixNano())},
	))

	batches := fake.batches()
	require.Len(t, batches, 1)
	require.Equal(t, map[string]int64{
		"inuse_space": 6144, "inuse_objects": 6, "alloc_space": 8192, "alloc_objects": 10,
	}, valuesByType(batches[0]))
	attrs := batches[0].ResourceProfiles().At(0).Resource().Attributes().AsRaw()
	require.Equal(t, "true", attrs["parca.agent"])
	require.EqualValues(t, 1000, attrs[attrProcessPID])
	require.NotContains(t, attrs, "service.name")
	require.Equal(t, "parca-agent", attrs["process.executable.name"])

	profiles := batches[0].ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles()
	for i := range profiles.Len() {
		require.Zero(t, profiles.At(i).DurationNano())
	}

	require.True(t, sink.WaitForProfile(1000, 0, time.Second))
}

func valuesByType(out pprofile.Profiles) map[string]int64 {
	dict := out.Dictionary()
	got := map[string]int64{}
	for i := range out.ResourceProfiles().Len() {
		sps := out.ResourceProfiles().At(i).ScopeProfiles()
		for j := range sps.Len() {
			profiles := sps.At(j).Profiles()
			for k := range profiles.Len() {
				p := profiles.At(k)
				name := dict.StringTable().At(int(p.SampleType().TypeStrindex()))
				for l := range p.Samples().Len() {
					values := p.Samples().At(l).Values()
					for m := range values.Len() {
						got[name] += values.At(m)
					}
				}
			}
		}
	}
	return got
}

// TestOTLPReporterMemoryProfilesAreInstant pins how an OOM heap snapshot is
// dated: at the instant it was read, with no duration, so consumers that
// derive temporality from the duration treat it as a snapshot rather than a
// delta. A CPU profile in the same batch keeps the flush window.
func TestOTLPReporterMemoryProfilesAreInstant(t *testing.T) {
	fake, conn := startFakeCollector(t)
	rep := newTestOTLPReporter(t, conn)
	rep.reportAllocs = true

	snapshotAt := uint64(time.Now().Add(-time.Minute).UnixNano())
	require.NoError(t, rep.ReportMemoryTraces(
		[]oomprof.Sample{{Addresses: []oomprof.Address{0x1000}, Allocs: 10, Frees: 4, AllocBytes: 8192, FreeBytes: 2048}},
		oomprof.SampleMeta{PID: 1000, Comm: "leaky", ExecutablePath: "/usr/bin/leaky", Timestamp: snapshotAt},
	))
	trace := &libpf.Trace{}
	trace.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x10})
	require.NoError(t, rep.ReportTraceEvent(trace, &samples.TraceEventMeta{
		ProfileType: testProfileTypeSampling,
		Timestamp:   libpf.UnixTime64(time.Now().UnixNano()),
		PID:         1000,
	}))
	require.NoError(t, rep.flush(context.Background()))

	out := fake.batches()[0]
	dict := out.Dictionary()
	seen := map[string]bool{}
	for i := range out.ResourceProfiles().Len() {
		profiles := out.ResourceProfiles().At(i).ScopeProfiles().At(0).Profiles()
		for j := range profiles.Len() {
			p := profiles.At(j)
			name := dict.StringTable().At(int(p.SampleType().TypeStrindex()))
			seen[name] = true
			if name == "samples" {
				require.NotZero(t, p.DurationNano(), "CPU profiles cover the flush window")
				continue
			}
			require.Zero(t, p.DurationNano(), "%s is a snapshot", name)
			require.EqualValues(t, snapshotAt, p.Time(), "%s is dated when it was read", name)
			for k := range p.Samples().Len() {
				require.Zero(t, p.Samples().At(k).TimestampsUnixNano().Len(),
					"%s samples carry no timestamps outside an empty interval", name)
			}
		}
	}
	for _, want := range []string{"samples", "inuse_space", "inuse_objects", "alloc_space", "alloc_objects"} {
		require.True(t, seen[want], "missing %s", want)
	}
}
