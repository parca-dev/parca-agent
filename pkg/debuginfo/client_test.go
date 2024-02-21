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

package debuginfo

import (
	"context"

	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	"google.golang.org/grpc"
)

type testClient struct {
	UploadF               func(opts ...grpc.CallOption) (debuginfopb.DebuginfoService_UploadClient, error)
	ShouldInitiateUploadF func(in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error)
	InitiateUploadF       func(in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error)
	MarkUploadFinishedF   func(in *debuginfopb.MarkUploadFinishedRequest, opts ...grpc.CallOption) (*debuginfopb.MarkUploadFinishedResponse, error)
}

func (c *testClient) Upload(ctx context.Context, opts ...grpc.CallOption) (debuginfopb.DebuginfoService_UploadClient, error) {
	if c.UploadF != nil {
		return c.UploadF(opts...)
	}
	return nil, nil
}

func (c *testClient) ShouldInitiateUpload(ctx context.Context, in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
	if c.ShouldInitiateUploadF != nil {
		return c.ShouldInitiateUploadF(in, opts...)
	}
	return &debuginfopb.ShouldInitiateUploadResponse{}, nil
}

func (c *testClient) InitiateUpload(ctx context.Context, in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
	if c.InitiateUploadF != nil {
		return c.InitiateUploadF(in, opts...)
	}
	return &debuginfopb.InitiateUploadResponse{}, nil
}

func (c *testClient) MarkUploadFinished(ctx context.Context, in *debuginfopb.MarkUploadFinishedRequest, opts ...grpc.CallOption) (*debuginfopb.MarkUploadFinishedResponse, error) {
	if c.MarkUploadFinishedF != nil {
		return c.MarkUploadFinishedF(in, opts...)
	}
	return &debuginfopb.MarkUploadFinishedResponse{}, nil
}
