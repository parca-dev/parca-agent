// Copyright 2022 The Parca Authors
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
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/google/pprof/profile"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

func BenchmarkEnsureUploadedAlreadyExists(b *testing.B) {
	name := filepath.Join("../../internal/pprof/binutils/testdata", "exe_linux_64")
	o, err := objectfile.Open(name, &profile.Mapping{
		Start:  0x5400000,
		Limit:  0x5401000,
		Offset: 0,
	})
	if err != nil {
		b.Fatal(err)
	}

	c := &NoopClient{
		ShouldInitiateUploadF: func(in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
			resp := debuginfopb.ShouldInitiateUploadResponse{
				ShouldInitiateUpload: true,
			}
			return &resp, nil
		},
		InitiateUploadF: func(in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "already exists")
		},
	}
	debuginfoProcessor := New(
		log.NewNopLogger(),
		prometheus.NewRegistry(),
		c,
		2*time.Minute,
		5*time.Minute,
		[]string{"/usr/lib/debug"},
		true,
		"/tmp",
	)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = debuginfoProcessor.ensureUploaded(
			ctx,
			&objectfile.MappedObjectFile{ObjectFile: o},
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}
