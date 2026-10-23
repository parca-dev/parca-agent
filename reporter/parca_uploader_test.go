package reporter

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	debuginfogrpc "buf.build/gen/go/parca-dev/parca/grpc/go/parca/debuginfo/v1alpha1/debuginfov1alpha1grpc"
	debuginfopb "buf.build/gen/go/parca-dev/parca/protocolbuffers/go/parca/debuginfo/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestMapShrink(t *testing.T) {
	tr := newInProgressTracker(0.2, 100)
	r := rand.New(rand.NewSource(0))

	items := make([]libpf.FileID, 100)
	for i := 0; i < 100; i++ {
		items[i] = libpf.NewFileID(
			r.Uint64(),
			r.Uint64(),
		)

		tr.TryAdd(items[i])
	}

	if tr.maxSizeSeen != 100 {
		t.Errorf("expected 100, got %d", tr.maxSizeSeen)
	}

	for i := 0; i < 10; i++ {
		tr.Remove(items[i])
	}

	if tr.maxSizeSeen != 100 {
		t.Errorf("expected 100, got %d", tr.maxSizeSeen)
	}

	for i := 10; i < 20; i++ {
		tr.Remove(items[i])
	}

	if tr.maxSizeSeen != 83 {
		t.Errorf("expected 83, got %d", tr.maxSizeSeen)
	}

	// adding up to 83 doesn't change anything
	for i := 10; i < 13; i++ {
		tr.TryAdd(items[i])
	}

	if tr.maxSizeSeen != 83 {
		t.Errorf("expected 83, got %d", tr.maxSizeSeen)
	}

	// adding 84th item should increases the max size
	tr.TryAdd(items[13])

	if tr.maxSizeSeen != 84 {
		t.Errorf("expected 84, got %d", tr.maxSizeSeen)
	}
}

type symbolUploadClient struct {
	debuginfogrpc.DebuginfoServiceClient
	should   func(*debuginfopb.ShouldInitiateUploadRequest) *debuginfopb.ShouldInitiateUploadResponse
	initiate func(*debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error)
	finish   func(*debuginfopb.MarkUploadFinishedRequest) error
	transfer func(*debuginfopb.UploadInfo, []byte)
}

func (c *symbolUploadClient) ShouldInitiateUpload(_ context.Context, req *debuginfopb.ShouldInitiateUploadRequest, _ ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
	if c.should != nil {
		return c.should(req), nil
	}
	return &debuginfopb.ShouldInitiateUploadResponse{ShouldInitiateUpload: true}, nil
}

func (c *symbolUploadClient) InitiateUpload(_ context.Context, req *debuginfopb.InitiateUploadRequest, _ ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
	return c.initiate(req)
}

func (c *symbolUploadClient) MarkUploadFinished(_ context.Context, req *debuginfopb.MarkUploadFinishedRequest, _ ...grpc.CallOption) (*debuginfopb.MarkUploadFinishedResponse, error) {
	return &debuginfopb.MarkUploadFinishedResponse{}, c.finish(req)
}

func (c *symbolUploadClient) Upload(context.Context, ...grpc.CallOption) (debuginfogrpc.DebuginfoService_UploadClient, error) {
	return &symbolUploadStream{transfer: c.transfer}, nil
}

type symbolUploadStream struct {
	grpc.ClientStream
	info     *debuginfopb.UploadInfo
	body     bytes.Buffer
	closed   bool
	transfer func(*debuginfopb.UploadInfo, []byte)
}

func (s *symbolUploadStream) Send(req *debuginfopb.UploadRequest) error {
	if info := req.GetInfo(); info != nil {
		s.info = info
	}
	s.body.Write(req.GetChunkData())
	return nil
}

func (s *symbolUploadStream) CloseAndRecv() (*debuginfopb.UploadResponse, error) {
	if !s.closed {
		s.transfer(s.info, s.body.Bytes())
		s.closed = true
	}
	return &debuginfopb.UploadResponse{Size: uint64(s.body.Len())}, nil
}

type symbolUploadTransport func(*http.Request) (*http.Response, error)

func (f symbolUploadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

const symbolUploadContent = "ELF artifact: abcdef0123456789\nnot a symmetric payload"

// Exercise the public queue and worker API. synctest advances retry timers without
// real sleeps and synchronizes observations with the idle worker.
func startSymbolUploader(t *testing.T, client *symbolUploadClient, transport symbolUploadTransport) (*ParcaSymbolUploader, func()) {
	t.Helper()
	dir := t.TempDir()
	fileName := filepath.Join(dir, "artifact")
	require.NoError(t, os.WriteFile(fileName, []byte(symbolUploadContent), 0o600))
	u, err := NewParcaSymbolUploader(client, 16, false, 4, 1, dir, prometheus.NewCounter(prometheus.CounterOpts{Name: "upload_bytes"}))
	require.NoError(t, err)
	u.httpClient = &http.Client{Transport: transport}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	return u, func() {
		u.Upload(ctx, libpf.NewFileID(1, 2), fileName, "build-id", func() (pfelf.ReadAtCloser, error) {
			return os.Open(fileName)
		})
		time.Sleep(10 * time.Second)
		synctest.Wait()
	}
}

func TestParcaSymbolUploaderInstructions(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, strategy := range []debuginfopb.UploadInstructions_UploadStrategy{
			debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC,
			debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL,
		} {
			name := "multiple/" + strategy.String()
			if legacy {
				name = "legacy/" + strategy.String()
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					transfers := 0
					var finished []string
					client := &symbolUploadClient{
						initiate: func(req *debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
							require.True(t, req.SupportsMultipleUploads)
							require.Equal(t, int64(len(symbolUploadContent)), req.Size)
							a := &debuginfopb.UploadInstructions{BuildId: req.BuildId, UploadId: "collector/a:original-id", UploadStrategy: strategy, SignedUrl: "https://storage.example/a", Type: req.Type}
							resp := &debuginfopb.InitiateUploadResponse{UploadTargets: []*debuginfopb.UploadInstructions{a}}
							if legacy {
								resp = &debuginfopb.InitiateUploadResponse{UploadInstructions: a}
							} else {
								resp.UploadTargets = append(resp.UploadTargets, &debuginfopb.UploadInstructions{BuildId: req.BuildId, UploadId: "collector/b:another-id", UploadStrategy: strategy, SignedUrl: "https://storage.example/b", Type: debuginfopb.DebuginfoType_DEBUGINFO_TYPE_EXECUTABLE})
							}
							// Future additive fields must not prevent reading known instructions.
							wire, err := proto.Marshal(resp)
							require.NoError(t, err)
							wire = protowire.AppendVarint(protowire.AppendTag(wire, 100, protowire.VarintType), 42)
							require.NoError(t, proto.Unmarshal(wire, resp))
							return resp, nil
						},
						finish: func(req *debuginfopb.MarkUploadFinishedRequest) error {
							require.Equal(t, "build-id", req.BuildId)
							if req.UploadId == "collector/b:another-id" {
								require.Equal(t, debuginfopb.DebuginfoType_DEBUGINFO_TYPE_EXECUTABLE, req.Type)
							}
							finished = append(finished, req.UploadId)
							return nil
						},
						transfer: func(info *debuginfopb.UploadInfo, body []byte) {
							require.Equal(t, "build-id", info.BuildId)
							require.Equal(t, symbolUploadContent, string(body))
							transfers++
						},
					}
					u, upload := startSymbolUploader(t, client, func(req *http.Request) (*http.Response, error) {
						body, err := io.ReadAll(req.Body)
						require.NoError(t, err)
						require.Equal(t, http.MethodPut, req.Method)
						require.Equal(t, int64(len(symbolUploadContent)), req.ContentLength)
						require.Equal(t, symbolUploadContent, string(body))
						transfers++
						return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
					})
					upload()
					want := []string{"collector/a:original-id"}
					if !legacy {
						want = append(want, "collector/b:another-id")
					}
					require.ElementsMatch(t, want, finished)
					require.Equal(t, len(want), transfers)
					require.Equal(t, float64(len(want)*len(symbolUploadContent)), testutil.ToFloat64(u.uploadRequestBytes))
					upload()
					require.Len(t, finished, len(want), "completed delivery must be cached")
				})
			})
		}
	}
}

func TestParcaSymbolUploaderRetriesIndependently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		puts, finishes := map[string]int{}, map[string]int{}
		negotiations := 0
		client := &symbolUploadClient{
			initiate: func(req *debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
				negotiations++
				resp := &debuginfopb.InitiateUploadResponse{}
				for _, id := range []string{"a", "b", "c"} {
					resp.UploadTargets = append(resp.UploadTargets, &debuginfopb.UploadInstructions{BuildId: req.BuildId, UploadId: id, UploadStrategy: debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL, SignedUrl: "https://storage.example/" + id})
				}
				return resp, nil
			},
			finish: func(req *debuginfopb.MarkUploadFinishedRequest) error {
				finishes[req.UploadId]++
				if req.UploadId == "b" && finishes["b"] == 1 {
					return status.Error(codes.Unavailable, "completion temporarily unavailable")
				}
				return nil
			},
		}
		_, upload := startSymbolUploader(t, client, func(req *http.Request) (*http.Response, error) {
			id := req.URL.Path[1:]
			puts[id]++
			if id == "a" && puts[id] == 1 {
				_, err := io.CopyN(io.Discard, req.Body, 7)
				require.NoError(t, err)
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody}, nil
			}
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, symbolUploadContent, string(body))
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		upload()
		require.Equal(t, map[string]int{"a": 2, "b": 1, "c": 1}, puts)
		require.Equal(t, map[string]int{"a": 1, "b": 2, "c": 1}, finishes)
		require.Equal(t, 1, negotiations, "retry known instructions rather than initiating again")
	})
}

func TestParcaSymbolUploaderRetryRequired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var negotiations, puts, finishes atomic.Int32
		attempts := make(chan time.Time, 3)
		unrelated := false
		client := &symbolUploadClient{
			should: func(req *debuginfopb.ShouldInitiateUploadRequest) *debuginfopb.ShouldInitiateUploadResponse {
				if req.BuildId == "unrelated" {
					unrelated = true
					return &debuginfopb.ShouldInitiateUploadResponse{}
				}
				return &debuginfopb.ShouldInitiateUploadResponse{ShouldInitiateUpload: true}
			},
			initiate: func(req *debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
				attempt := negotiations.Add(1)
				attempts <- time.Now()
				if attempt == 2 {
					return &debuginfopb.InitiateUploadResponse{RetryRequired: true}, nil
				}
				return &debuginfopb.InitiateUploadResponse{
					UploadTargets: []*debuginfopb.UploadInstructions{{BuildId: req.BuildId, UploadId: "opaque", UploadStrategy: debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL, SignedUrl: "https://storage.example/artifact"}},
					RetryRequired: attempt == 1,
				}, nil
			},
			finish: func(*debuginfopb.MarkUploadFinishedRequest) error { finishes.Add(1); return nil },
		}
		u, upload := startSymbolUploader(t, client, func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, symbolUploadContent, string(body))
			puts.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		upload()
		require.EqualValues(t, 1, negotiations.Load(), "a server retry hint must not trigger second-scale renegotiation")
		require.EqualValues(t, 1, finishes.Load(), "supplied targets must complete before deferring")
		upload()
		u.Upload(context.Background(), libpf.NewFileID(3, 4), "", "unrelated", nil)
		synctest.Wait()
		require.True(t, unrelated, "a deferred retry must not occupy the only worker")
		for round := 1; round <= 2; round++ {
			due := (<-attempts).Add(5 * time.Minute)
			time.Sleep(time.Until(due) - time.Nanosecond)
			synctest.Wait()
			require.EqualValues(t, round, negotiations.Load(), "no retry before five minutes, even after another Upload call")
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			require.EqualValues(t, round+1, negotiations.Load(), "retry must happen without another Upload call")
		}
		require.EqualValues(t, 3, negotiations.Load())
		require.EqualValues(t, 2, puts.Load())
		require.EqualValues(t, 2, finishes.Load())
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		upload()
		require.EqualValues(t, 3, negotiations.Load(), "successful delivery must stop scheduled retries")
	})
}

func TestParcaSymbolUploaderPreflightCompatibility(t *testing.T) {
	for _, response := range []*debuginfopb.ShouldInitiateUploadResponse{
		{RetryRequired: true},
		{Reason: ReasonUploadInProgress},
		{},
	} {
		synctest.Test(t, func(t *testing.T) {
			var checks atomic.Int32
			negotiations := 0
			client := &symbolUploadClient{
				should: func(*debuginfopb.ShouldInitiateUploadRequest) *debuginfopb.ShouldInitiateUploadResponse {
					if checks.Add(1) > 1 {
						return &debuginfopb.ShouldInitiateUploadResponse{}
					}
					return response
				},
				initiate: func(*debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
					negotiations++
					return &debuginfopb.InitiateUploadResponse{}, nil
				},
			}
			_, upload := startSymbolUploader(t, client, nil)
			start := time.Now()
			upload()
			upload()
			require.EqualValues(t, 1, checks.Load())
			require.Zero(t, negotiations)
			time.Sleep(time.Until(start.Add(5*time.Minute)) - time.Nanosecond)
			synctest.Wait()
			require.EqualValues(t, 1, checks.Load())
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			wantChecks := 1
			if response.RetryRequired || response.Reason == ReasonUploadInProgress {
				wantChecks = 2
			}
			require.EqualValues(t, wantChecks, checks.Load())
		})
	}
}

func TestParcaSymbolUploaderUnknownStrategy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var negotiations, finishes atomic.Int32
		client := &symbolUploadClient{
			initiate: func(req *debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
				negotiations.Add(1)
				return &debuginfopb.InitiateUploadResponse{UploadTargets: []*debuginfopb.UploadInstructions{
					{BuildId: req.BuildId, UploadId: "future", UploadStrategy: 42},
					{BuildId: req.BuildId, UploadId: "supported", UploadStrategy: debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL, SignedUrl: "https://storage.example/artifact"},
				}}, nil
			},
			finish: func(req *debuginfopb.MarkUploadFinishedRequest) error {
				require.Equal(t, "supported", req.UploadId, "never complete an unsupported instruction")
				finishes.Add(1)
				return nil
			},
		}
		_, upload := startSymbolUploader(t, client, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		upload()
		require.EqualValues(t, 1, finishes.Load(), "an unknown strategy must not prevent supported targets from completing")
		upload()
		require.EqualValues(t, 1, negotiations.Load(), "retry budget exhaustion must back off")
		time.Sleep(5*time.Minute + time.Second)
		upload()
		require.EqualValues(t, 2, negotiations.Load(), "an unknown future strategy must not permanently cache delivery as complete")
	})
}

func TestParcaSymbolUploaderNegotiationFailures(t *testing.T) {
	for _, code := range []codes.Code{codes.FailedPrecondition, codes.Unavailable, codes.AlreadyExists, codes.InvalidArgument} {
		t.Run(code.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var negotiations atomic.Int32
				client := &symbolUploadClient{
					initiate: func(*debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
						negotiations.Add(1)
						return nil, status.Error(code, "upload refused")
					},
				}
				_, upload := startSymbolUploader(t, client, nil)
				upload()
				terminal := code == codes.AlreadyExists || code == codes.InvalidArgument
				if terminal {
					require.EqualValues(t, 1, negotiations.Load())
				} else {
					require.EqualValues(t, 3, negotiations.Load(), "negotiation retries must be bounded")
				}
				upload()
				before := negotiations.Load()
				time.Sleep(5*time.Minute + time.Second)
				upload()
				if terminal {
					require.Equal(t, before, negotiations.Load())
				} else {
					require.Greater(t, negotiations.Load(), before, "a temporary refusal must remain retryable")
				}
			})
		})
	}
}

func TestParcaSymbolUploaderCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := &symbolUploadClient{
			initiate: func(req *debuginfopb.InitiateUploadRequest) (*debuginfopb.InitiateUploadResponse, error) {
				cancel()
				return nil, ctx.Err()
			},
		}
		u, err := NewParcaSymbolUploader(client, 16, false, 4, 1, t.TempDir(), prometheus.NewCounter(prometheus.CounterOpts{Name: "upload_bytes"}))
		require.NoError(t, err)
		fileName := filepath.Join(t.TempDir(), "artifact")
		require.NoError(t, os.WriteFile(fileName, []byte(symbolUploadContent), 0o600))
		u.Upload(ctx, libpf.NewFileID(1, 2), fileName, "build-id", func() (pfelf.ReadAtCloser, error) { return os.Open(fileName) })
		start := time.Now()
		require.NoError(t, u.Run(ctx))
		require.Less(t, time.Since(start), time.Second, "cancellation must interrupt retry backoff")
	})
}

func TestParcaSymbolUploaderDeferredCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var checks atomic.Int32
		client := &symbolUploadClient{
			should: func(*debuginfopb.ShouldInitiateUploadRequest) *debuginfopb.ShouldInitiateUploadResponse {
				checks.Add(1)
				return &debuginfopb.ShouldInitiateUploadResponse{RetryRequired: true}
			},
		}
		u, err := NewParcaSymbolUploader(client, 2, false, 4, 1, t.TempDir(), prometheus.NewCounter(prometheus.CounterOpts{Name: "upload_bytes"}))
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() { done <- u.Run(ctx) }()
		for id := uint64(1); id <= 3; id++ {
			u.Upload(ctx, libpf.NewFileID(id, 0), "", "build-id", nil)
			synctest.Wait()
		}
		require.EqualValues(t, 2, checks.Load(), "deferred requests must be bounded by the cache size")
		cancel()
		require.NoError(t, <-done, "shutdown must not wait for the five-minute retry delay")
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		require.EqualValues(t, 2, checks.Load(), "shutdown must cancel scheduled retries")
	})
}
