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

package e2e

import (
	"context"
	"testing"

	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/parca-dev/parca/gen/proto/go/parca/query/v1alpha1"
)

func TestIntegrationGRPC(t *testing.T) {
	conn, err := grpc.Dial("127.0.0.1:7070", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	c := pb.NewQueryServiceClient(conn)
	ctx := context.Background()

	queryRequest := &pb.QueryRangeRequest{
		Query: `parca_agent_cpu:samples:count:cpu:nanoseconds:delta{container="parca-agent"}`,
		Start: timestamppb.New(timestamp.Time(0)),
		End:   timestamppb.New(timestamp.Time(9223372036854775807)),
		Limit: 10,
	}

	resp, err := c.QueryRange(ctx, queryRequest)

	require.NoError(t, err)
	require.NotEmpty(t, resp.Series)
}
