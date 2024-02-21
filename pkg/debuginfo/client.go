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

type NoopClient struct{}

func (c *NoopClient) Upload(ctx context.Context, opts ...grpc.CallOption) (debuginfopb.DebuginfoService_UploadClient, error) {
	return nil, nil
}

func (c *NoopClient) ShouldInitiateUpload(ctx context.Context, in *debuginfopb.ShouldInitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.ShouldInitiateUploadResponse, error) {
	return &debuginfopb.ShouldInitiateUploadResponse{}, nil
}

func (c *NoopClient) InitiateUpload(ctx context.Context, in *debuginfopb.InitiateUploadRequest, opts ...grpc.CallOption) (*debuginfopb.InitiateUploadResponse, error) {
	return &debuginfopb.InitiateUploadResponse{}, nil
}

func (c *NoopClient) MarkUploadFinished(ctx context.Context, in *debuginfopb.MarkUploadFinishedRequest, opts ...grpc.CallOption) (*debuginfopb.MarkUploadFinishedResponse, error) {
	return &debuginfopb.MarkUploadFinishedResponse{}, nil
}

func NewNoopClient() *NoopClient {
	return &NoopClient{}
}
