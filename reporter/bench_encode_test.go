// SPDX-License-Identifier: Apache-2.0

// Encoder benchmarks: replay a real corpus through each backend with the
// tracer, eBPF, unwind-table extraction and a real backend removed, leaving
// labels, dictionary interning and serialization. Whole-agent measurements
// cannot compare the encoders, because on a host with process churn
// elfExtractor.parseFDE allocates more than everything else combined.
//
//	PARCA_BENCH_CORPUS=~/parca-agent-offline/x.padata.zst \
//	  go test ./reporter/ -run '^$' -bench Encode -benchmem
package reporter

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	profilestorev1alpha1grpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/profilestore/v1alpha1/profilestorev1alpha1grpc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/parca-dev/parca-agent/reporter/metadata"
)

// benchEvents caps the corpus per iteration: one flush interval's worth. 20k at
// the ~370 samples/s seen under load is about a minute of profiling, well past
// the point where dictionary reuse has settled.
const benchEvents = 20000

// rawCodec is what makes the endpoint a true /dev/null: the server never
// decodes a request, it just counts the bytes.
//
// Registering the generated services instead would charge the client's process
// for the server's unmarshal, and that cost is wildly asymmetric -- an arrow
// WriteArrowRequest is one bytes field, while an OTLP ExportRequest rebuilds
// every Sample, Stack and Location in pdata. The agent never pays that, so
// neither should the measurement.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.(*rawMessage); ok {
		return b.data, nil
	}
	// Responses: an empty protobuf is a valid empty message of any type, which
	// is all the client needs back.
	return nil, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*rawMessage); ok {
		b.data = data
	}
	return nil
}

type rawMessage struct{ data []byte }

// newNullEndpoint returns a connection to an in-process server that accepts any
// method, decodes nothing, and replies with an empty message. The client side
// is untouched -- real codec, real compression, real HTTP/2 framing -- so
// everything the agent pays for is still measured.
func newNullEndpoint(tb testing.TB) *grpc.ClientConn {
	tb.Helper()

	lis := bufconn.Listen(16 << 20)
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(512<<20),
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
			var in rawMessage
			if err := stream.RecvMsg(&in); err != nil {
				return err
			}
			return stream.SendMsg(&rawMessage{})
		}),
	)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(512<<20)),
	)
	require.NoError(tb, err)

	tb.Cleanup(func() {
		conn.Close()
		srv.Stop()
		lis.Close()
	})
	return conn
}

// benchLabeler is the label pipeline with every metadata provider removed. The
// providers read /proc, which would put filesystem latency into the measurement
// and make it depend on whatever else is running.
func benchLabeler(tb testing.TB) *processLabeler {
	tb.Helper()

	labels, err := lru.NewSynced[libpf.PID, labelRetrievalResult](8192, libpf.PID.Hash32)
	require.NoError(tb, err)

	return &processLabeler{labels: labels, nodeName: "bench-node"}
}

func benchExecutables(tb testing.TB) *lru.SyncedLRU[libpf.FileID, metadata.ExecInfo] {
	tb.Helper()
	execs, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](16384, libpf.FileID.Hash32)
	require.NoError(tb, err)
	return execs
}

func newBenchOTLPReporter(tb testing.TB, conn *grpc.ClientConn) *otlpProfilesReporter {
	tb.Helper()
	reg := prometheus.NewRegistry()
	return &otlpProfilesReporter{
		client:           pprofileotlp.NewGRPCClient(conn),
		builder:          newPprofileBuilder(benchExecutables(tb), "bench-node"),
		windowStart:      time.Now().Add(-5 * time.Second),
		labeler:          benchLabeler(tb),
		counters:         newReporterCounters(reg),
		samplesPerSecond: 19,
		reportInterval:   5 * time.Second,
		exportedSamples:  prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_samples"}),
		exportFailures:   prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_failures"}),
		exportedBytes:    prometheus.NewCounter(prometheus.CounterOpts{Name: "bench_bytes"}),
	}
}

func newBenchArrowReporter(tb testing.TB, conn *grpc.ClientConn) *arrowReporter {
	tb.Helper()
	reg := prometheus.NewRegistry()

	// The stack cache is the arrow path's twin of the pprofile dictionary: it
	// is what makes a repeated stack cheap, so it has to be present or the
	// comparison flatters OTLP.
	stacks, err := lru.NewSynced[libpf.TraceHash, libpf.Frames](16384, libpf.TraceHash.Hash32)
	require.NoError(tb, err)

	counter := func(name string) prometheus.Counter {
		return prometheus.NewCounter(prometheus.CounterOpts{Name: name})
	}

	return &arrowReporter{
		stopSignal:       make(chan libpf.Void),
		client:           profilestorev1alpha1grpc.NewProfileStoreServiceClient(conn),
		executables:      benchExecutables(tb),
		lbls:             benchLabeler(tb),
		counters:         newReporterCounters(reg),
		useV2Schema:      true,
		sampleWriterV2:   NewSampleWriterV2(memory.DefaultAllocator),
		stacks:           stacks,
		mem:              memory.DefaultAllocator,
		samplesPerSecond: 19,
		reportInterval:   5 * time.Second,
		nodeName:         "bench-node",

		sampleWrites:                counter("bench_sample_writes"),
		sampleWriteRequestBytes:     counter("bench_sample_bytes"),
		stacktraceWriteRequestBytes: counter("bench_stacktrace_bytes"),
		writeRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "bench_write_requests"}, []string{"code"}),
	}
}

// corpusStats describes what was replayed, so a result can be read against the
// shape that produced it rather than against a row count alone.
type corpusStats struct {
	events, frames int
	pids, mappings int
}

func statsFor(events []traceEvent) corpusStats {
	s := corpusStats{events: len(events)}
	pids := make(map[libpf.PID]struct{})
	maps := make(map[libpf.FileID]struct{})
	for _, e := range events {
		pids[e.meta.PID] = struct{}{}
		for _, uf := range e.trace.Frames {
			s.frames++
			if m := uf.Value().Mapping; m.Valid() {
				maps[m.Value().File.Value().FileID] = struct{}{}
			}
		}
	}
	s.pids, s.mappings = len(pids), len(maps)
	return s
}

func (s corpusStats) report(b *testing.B) {
	b.ReportMetric(float64(s.events), "samples/op")
	b.ReportMetric(float64(s.frames)/float64(s.events), "frames/sample")
	b.ReportMetric(float64(s.pids), "pids")
	b.ReportMetric(float64(s.mappings), "mappings")
}

// BenchmarkEncodeOTLP is one whole flush interval on the OTLP path: accumulate
// the batch, build the pprofile dictionaries, marshal, and send.
func BenchmarkEncodeOTLP(b *testing.B) {
	events := loadBenchCorpus(b, benchEvents)
	stats := statsFor(events)
	conn := newNullEndpoint(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		b.StopTimer()
		r := newBenchOTLPReporter(b, conn)
		b.StartTimer()

		for _, e := range events {
			if err := r.ReportTraceEvent(e.trace, e.meta); err != nil {
				b.Fatal(err)
			}
		}
		if err := r.flush(ctx); err != nil {
			b.Fatal(err)
		}
	}

	b.StopTimer()
	stats.report(b)
}

// BenchmarkEncodeArrowV2 is the same workload through the arrow v2 path.
func BenchmarkEncodeArrowV2(b *testing.B) {
	events := loadBenchCorpus(b, benchEvents)
	stats := statsFor(events)
	conn := newNullEndpoint(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		b.StopTimer()
		r := newBenchArrowReporter(b, conn)
		var buf bytes.Buffer
		b.StartTimer()

		for _, e := range events {
			if err := r.ReportTraceEvent(e.trace, e.meta); err != nil {
				b.Fatal(err)
			}
		}
		if err := r.reportDataToBackendV2(ctx, &buf); err != nil {
			b.Fatal(err)
		}
	}

	b.StopTimer()
	stats.report(b)
}

// BenchmarkEncodeOTLPAccumulate drops the flush, so no marshal and no send. The
// gap against BenchmarkEncodeOTLP is what the flush costs.
func BenchmarkEncodeOTLPAccumulate(b *testing.B) {
	events := loadBenchCorpus(b, benchEvents)
	conn := newNullEndpoint(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		b.StopTimer()
		r := newBenchOTLPReporter(b, conn)
		b.StartTimer()

		for _, e := range events {
			if err := r.ReportTraceEvent(e.trace, e.meta); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(events)), "samples/op")
}

// BenchmarkEncodeArrowV2Accumulate is the arrow twin of the above.
func BenchmarkEncodeArrowV2Accumulate(b *testing.B) {
	events := loadBenchCorpus(b, benchEvents)
	conn := newNullEndpoint(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		b.StopTimer()
		r := newBenchArrowReporter(b, conn)
		b.StartTimer()

		for _, e := range events {
			if err := r.ReportTraceEvent(e.trace, e.meta); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(events)), "samples/op")
}

var _ = memory.DefaultAllocator
