// Copyright 2022-2023 The Parca Authors
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

package debuginfo

import (
	"bytes"
	"context"
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
	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

func BenchmarkUploadInitiateUploadError(b *testing.B) {
	name := filepath.Join("../../internal/pprof/binutils/testdata", "exe_linux_64")
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 1024)
	b.Cleanup(func() {
		objFilePool.Close()
	})
	o, err := objFilePool.Open(name)
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
		prometheus.NewRegistry(),
		objFilePool,
		c,
		25,
		2*time.Minute,
		5*time.Minute,
		[]string{"/usr/lib/debug"},
		true,
		"/tmp",
	)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = debuginfoManager.upload(ctx, o)
		require.Equal(b, codes.Internal, status.Code(errors.Unwrap(err)))
	}
}

func TestUpload(t *testing.T) {
	name := filepath.Join("../../internal/pprof/binutils/testdata", "exe_linux_64")
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 1024)
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
		prometheus.NewRegistry(),
		objFilePool,
		c,
		25,
		2*time.Minute,
		5*time.Minute,
		[]string{"/usr/lib/debug"},
		true,
		"/tmp",
	)

	// Upload: 1 (canceled)
	err = dim.Upload(context.Background(), dbgFile)
	require.Error(t, err)

	// Assert metrics were incremented.
	require.Equal(t, 1.0, testutil.ToFloat64(dim.metrics.uploadRequests))
	require.Equal(t, 1.0, testutil.ToFloat64(dim.metrics.uploadAttempts))
	require.Equal(t, 1.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvFail)))

	// Upload: 2 (error)
	err = dim.Upload(context.Background(), dbgFile)
	require.Error(t, err)

	// Assert metrics were incremented.
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.uploadRequests))
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.uploadAttempts))
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvFail)))

	// Upload: 3 (success)
	err = dim.Upload(context.Background(), dbgFile)
	require.NoError(t, err)

	// Assert metrics were incremented.
	require.Equal(t, 3.0, testutil.ToFloat64(dim.metrics.uploadRequests))
	require.Equal(t, 3.0, testutil.ToFloat64(dim.metrics.uploadAttempts))
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvFail)))

	// Assert the upload was successful.
	require.Equal(t, 1.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvSuccess)))

	// Upload: 4 (already exists)
	err = dim.Upload(context.Background(), dbgFile)
	require.NoError(t, err)

	// Assert metrics were incremented.
	require.Equal(t, 4.0, testutil.ToFloat64(dim.metrics.uploadRequests))
	require.Equal(t, 4.0, testutil.ToFloat64(dim.metrics.uploadAttempts))
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvFail)))
	// Already exists is not a failure.
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvSuccess)))

	// Upload: 5 (cached)
	err = dim.Upload(context.Background(), dbgFile)
	require.NoError(t, err)

	// Assert metrics were incremented.
	require.Equal(t, 5.0, testutil.ToFloat64(dim.metrics.uploadRequests))
	// When the response is cached, the upload is not attempted.
	require.Equal(t, 4.0, testutil.ToFloat64(dim.metrics.uploadAttempts))
	require.Equal(t, 2.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvFail)))
	require.Equal(t, 3.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvSuccess)))
}

func TestUploadSingleFlight(t *testing.T) {
	name := filepath.Join("../../internal/pprof/binutils/testdata", "exe_linux_64")
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 1024)
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
		prometheus.NewRegistry(),
		objFilePool,
		c,
		5,
		2*time.Minute,
		5*time.Minute,
		[]string{"/usr/lib/debug"},
		true,
		"/tmp",
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

			err = dim.Upload(context.Background(), dbgFile)
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	close(done)

	require.Equal(t, 10.0, testutil.ToFloat64(dim.metrics.uploadRequests))
	require.Equal(t, 1.0, testutil.ToFloat64(dim.metrics.uploadAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvFail)))
	require.Equal(t, 5.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvShared)))
	require.Equal(t, 10.0, testutil.ToFloat64(dim.metrics.upload.WithLabelValues(lvSuccess)))
}

func TestDisableStripping(t *testing.T) {
	file := "./testdata/readelf-sections"
	originalContent, err := os.ReadFile(file)
	require.NoError(t, err)

	m := &Manager{
		stripDebuginfos: false,
		tempDir:         os.TempDir(),
	}
	objFilePool := objectfile.NewPool(log.NewNopLogger(), prometheus.NewRegistry(), 5)
	t.Cleanup(func() {
		objFilePool.Close()
	})
	objFile, err := objFilePool.Open(file)
	require.NoError(t, err)

	// buildid: "test"
	f, err := m.extractDebuginfo(context.Background(), objFile)
	require.NoError(t, err)

	r, done, err := f.Reader()
	require.NoError(t, err)
	t.Cleanup(func() {
		done()
	})
	strippedContent, err := io.ReadAll(r)
	require.NoError(t, err)

	if !bytes.Equal(originalContent, strippedContent) {
		t.Fatal("stripped file content is not equal to original file content")
	}
}
