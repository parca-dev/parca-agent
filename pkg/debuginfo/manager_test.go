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
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
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
	if err != nil {
		b.Fatal(err)
	}

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
	debuginfoManager, err := New(
		log.NewNopLogger(),
		prometheus.NewRegistry(),
		objFilePool,
		c,
		2*time.Minute,
		3,
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

func TestHasTextSection(t *testing.T) {
	testCases := []struct {
		name              string
		filepath          string
		textSectionExists bool
		wantErr           bool
	}{
		{
			name:              "text section present",
			filepath:          "./testdata/readelf-sections",
			textSectionExists: true,
			wantErr:           false,
		},
		{
			name:              "text section absent",
			filepath:          "./testdata/elf-file-without-text-section",
			textSectionExists: false,
			wantErr:           false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.filepath)
			t.Cleanup(func() {
				f.Close()
			})
			require.NoError(t, err)

			ef, err := elf.NewFile(f)
			require.NoError(t, err)

			ok, err := hasTextSection(ef)
			if !tc.wantErr {
				require.NoError(t, err)
			}

			require.Equal(t, tc.textSectionExists, ok)
		})
	}
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
	f, err := m.stripDebuginfo(context.Background(), objFile)
	require.NoError(t, err)

	strippedContent, err := os.ReadFile(f.File.Name())
	require.NoError(t, err)

	if !bytes.Equal(originalContent, strippedContent) {
		t.Fatal("stripped file content is not equal to original file content")
	}
}
