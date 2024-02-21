// Copyright 2022-2024 The Parca Authors
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
//

// nolint:testifylint
package debuginfo

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

func BenchmarkUploadInitiateUploadError(b *testing.B) {
	name := filepath.Join("./testdata", "exe_linux_64")
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), "", 10, 0)
	b.Cleanup(func() {
		objFilePool.Close()
	})
	obj, err := objFilePool.Open(name)
	require.NoError(b, err)

	c := &testClient{
		ShouldInitiateUploadF: func(in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
			resp := debuginfopb.ShouldInitiateUploadResponse{
				ShouldInitiateUpload: true,
			}
			return &resp, nil
		},
		InitiateUploadF: func(in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
			return nil, status.Error(codes.Internal, "internal")
		},
	}
	debuginfoManager := New(
		log.NewNopLogger(),
		noop.NewTracerProvider(),
		prometheus.NewRegistry(),
		objFilePool,
		c,
		ManagerConfig{
			UploadMaxParallel:     25,
			UploadTimeout:         2 * time.Minute,
			CachingDisabled:       false,
			DebugDirs:             []string{"/usr/lib/debug"},
			StripDebuginfos:       true,
			CompressDWARFSections: false,
			TempDir:               "/tmp",
		},
	)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = debuginfoManager.upload(ctx, obj)
		require.Equal(b, codes.Internal, status.Code(errors.Unwrap(err)))
	}
}

func TestUpload(t *testing.T) {
	name := filepath.Join("./testdata", "exe_linux_64")
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), "", 10, 0)
	t.Cleanup(func() {
		objFilePool.Close()
	})

	// Create a mock object file.
	dbgFile, err := objFilePool.Open(name)
	require.NoError(t, err)

	counter := atomic.NewInt32(1)
	// Create a mock server to inject errors.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { counter.Add(1) }()
		switch {
		case counter.Load() < 2:
			w.WriteHeader(http.StatusNotFound) // 4xx error.
			fmt.Fprintln(w, "client-side error")
		case counter.Load() == 2:
			w.WriteHeader(http.StatusInternalServerError) // 5xx error.
			fmt.Fprintln(w, "server-side error")
		case counter.Load() == 3:
			fmt.Fprintln(w, "uploaded")
		case counter.Load() > 3:
			w.WriteHeader(http.StatusAlreadyReported)
		default:
			fmt.Fprintln(w, "Hello, client")
		}
	}))
	t.Cleanup(func() {
		testServer.Close()
	})

	// Create a mock client.
	c := &testClient{
		ShouldInitiateUploadF: func(in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
			resp := debuginfopb.ShouldInitiateUploadResponse{
				ShouldInitiateUpload: true,
			}
			return &resp, nil
		},
		InitiateUploadF: func(in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
			if counter.Load() > 3 {
				return nil, status.Error(codes.AlreadyExists, "already exists")
			}
			return &debuginfopb.InitiateUploadResponse{
				UploadInstructions: &debuginfopb.UploadInstructions{
					UploadId:       "upload-id",
					BuildId:        dbgFile.BuildID,
					UploadStrategy: debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL,
					SignedUrl:      testServer.URL,
				},
			}, nil
		},
		MarkUploadFinishedF: func(in *debuginfopb.MarkUploadFinishedRequest, opts ...grpc.CallOption) (*debuginfopb.MarkUploadFinishedResponse, error) {
			return &debuginfopb.MarkUploadFinishedResponse{}, nil
		},
	}

	// Create a Manager instance.
	dim := New(
		log.NewNopLogger(),
		noop.NewTracerProvider(),
		prometheus.NewRegistry(),
		objFilePool,
		c,
		ManagerConfig{
			UploadMaxParallel:     25,
			UploadTimeout:         2 * time.Minute,
			CachingDisabled:       false,
			DebugDirs:             []string{"/usr/lib/debug"},
			StripDebuginfos:       true,
			CompressDWARFSections: false,
			TempDir:               "/tmp",
		},
	)

	// Upload: 1 (canceled)
	err = dim.Upload(context.Background(), dbgFile)
	require.Error(t, err)

	// Assert metrics were incremented.
	require.InEpsilon(t, 1.0, testutil.ToFloat64(dim.metrics.uploadRequests), 1e-12)
	require.InEpsilon(t, 1.0, testutil.ToFloat64(dim.metrics.uploadAttempts), 1e-12)
	require.InEpsilon(t, 1.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvFail)), 1e-12)

	// Upload: 2 (error)
	err = dim.Upload(context.Background(), dbgFile)
	require.Error(t, err)

	// Assert metrics were incremented.
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploadRequests), 1e-12)
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploadAttempts), 1e-12)
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvFail)), 1e-12)

	// Upload: 3 (success)
	err = dim.Upload(context.Background(), dbgFile)
	require.NoError(t, err)

	// Assert metrics were incremented.
	require.InEpsilon(t, 3.0, testutil.ToFloat64(dim.metrics.uploadRequests), 1e-12)
	require.InEpsilon(t, 3.0, testutil.ToFloat64(dim.metrics.uploadAttempts), 1e-12)
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvFail)), 1e-12)

	// Assert the upload was successful.
	require.InEpsilon(t, 1.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvSuccess)), 1e-12)

	// Upload: 4 (already exists)
	err = dim.Upload(context.Background(), dbgFile)
	require.NoError(t, err)

	// Assert metrics were incremented.
	require.InEpsilon(t, 4.0, testutil.ToFloat64(dim.metrics.uploadRequests), 1e-12)
	require.InEpsilon(t, 4.0, testutil.ToFloat64(dim.metrics.uploadAttempts), 1e-12)
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvFail)), 1e-12)
	// Already exists is not a failure.
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvSuccess)), 1e-12)

	// Upload: 5 (cached)
	err = dim.Upload(context.Background(), dbgFile)
	require.NoError(t, err)

	// Assert metrics were incremented.
	require.InEpsilon(t, 5.0, testutil.ToFloat64(dim.metrics.uploadRequests), 1e-12)
	// When the response is cached, the upload is not attempted.
	require.InEpsilon(t, 5.0, testutil.ToFloat64(dim.metrics.uploadAttempts), 1e-12)
	require.InEpsilon(t, 2.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvFail)), 1e-12)
	require.InEpsilon(t, 3.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvSuccess)), 1e-12)
}

func TestUploadSingleFlight(t *testing.T) {
	name := filepath.Join("./testdata", "exe_linux_64")
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), "", 10, 0)
	t.Cleanup(func() {
		objFilePool.Close()
	})

	// Create a mock object file.
	dbgFile, err := objFilePool.Open(name)
	require.NoError(t, err)

	inflight := atomic.NewUint32(0)
	counter := atomic.NewUint32(0)
	// Create a mock server to inject errors.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Inc()
		defer inflight.Dec()

		counter.Inc()

		time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond) //nolint:gosec
		fmt.Fprintln(w, "Hello, client")
	}))
	t.Cleanup(func() {
		testServer.Close()
	})

	// Create a mock client.
	c := &testClient{
		ShouldInitiateUploadF: func(in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
			resp := debuginfopb.ShouldInitiateUploadResponse{
				ShouldInitiateUpload: counter.Load() < 1,
			}
			return &resp, nil
		},
		InitiateUploadF: func(in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
			if counter.Load() >= 1 {
				return nil, status.Error(codes.AlreadyExists, "already exists")
			}
			return &debuginfopb.InitiateUploadResponse{
				UploadInstructions: &debuginfopb.UploadInstructions{
					UploadId:       "upload-id",
					BuildId:        dbgFile.BuildID,
					UploadStrategy: debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL,
					SignedUrl:      testServer.URL,
				},
			}, nil
		},
		MarkUploadFinishedF: func(in *debuginfopb.MarkUploadFinishedRequest, opts ...grpc.CallOption) (*debuginfopb.MarkUploadFinishedResponse, error) {
			return &debuginfopb.MarkUploadFinishedResponse{}, nil
		},
	}

	// Create a Manager instance.
	dim := New(
		log.NewNopLogger(),
		noop.NewTracerProvider(),
		prometheus.NewRegistry(),
		objFilePool,
		c,
		ManagerConfig{
			UploadMaxParallel:     5,
			UploadTimeout:         2 * time.Minute,
			CachingDisabled:       false,
			DebugDirs:             []string{"/usr/lib/debug"},
			StripDebuginfos:       true,
			CompressDWARFSections: false,
			TempDir:               "/tmp",
		},
	)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				// There should be only one upload in flight.
				require.LessOrEqualf(t, inflight.Load(), uint32(1), "there should be only one upload in flight")
				require.LessOrEqualf(t, testutil.ToFloat64(dim.metrics.uploadInflight), 5.0, "there should be only max number of upload requests started")
			}
		}
	}()

	wg := &sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := dim.Upload(context.Background(), dbgFile)
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	close(done)

	require.InEpsilon(t, 10.0, testutil.ToFloat64(dim.metrics.uploadRequests), 1e-12) // Critical metrics.
	require.InEpsilon(t, 1.0, testutil.ToFloat64(dim.metrics.uploadInitiated), 1e-12) // Critical metrics.
	require.InDelta(t, 0.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvFail)), 1e-12)
	require.InEpsilon(t, 10.0, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvSuccess)), 1e-12)
	require.GreaterOrEqual(t, testutil.ToFloat64(dim.metrics.uploaded.WithLabelValues(lvShared)), 5.0)
}

func TestDisableStripping(t *testing.T) {
	file := "./testdata/readelf-sections"
	originalContent, err := os.ReadFile(file)
	require.NoError(t, err)

	m := &Manager{
		logger: log.NewNopLogger(),
		tracer: noop.NewTracerProvider().Tracer("test"),
		config: ManagerConfig{
			StripDebuginfos: false,
			TempDir:         os.TempDir(),
		},
	}
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), "", 10, 0)

	obj, err := objFilePool.Open(file)
	require.NoError(t, err)

	// buildid: "test"
	dbg, err := m.Extract(context.Background(), obj)
	require.NoError(t, err)

	r, err := dbg.Reader()
	require.NoError(t, err)

	strippedContent, err := io.ReadAll(r)
	require.NoError(t, err)

	if !bytes.Equal(originalContent, strippedContent) {
		t.Fatal("stripped file content is not equal to original file content")
	}
}

func TestHasTextSection(t *testing.T) {
	testCases := []struct {
		name              string
		filepath          string
		textSectionExists bool
	}{
		{
			name:              "text section present",
			filepath:          "./testdata/readelf-sections",
			textSectionExists: true,
		},
		{
			name:              "text section absent",
			filepath:          "./testdata/elf-file-without-text-section",
			textSectionExists: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ef, err := elf.Open(tc.filepath)
			require.NoError(t, err)
			t.Cleanup(func() {
				ef.Close()
			})

			require.Equal(t, tc.textSectionExists, hasTextSection(ef))
		})
	}
}
