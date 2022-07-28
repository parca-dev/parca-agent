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
	"math"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/parca-dev/parca/gen/proto/go/parca/query/v1alpha1"
)

func TestIntegrationGRPC(t *testing.T) {
	println("starting tests")
	conn, err := grpc.Dial("127.0.0.1:7070", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	println("Creating query service client")
	c := pb.NewQueryServiceClient(conn)
	ctx := context.Background()

	println("Performing Query Range Request")
	queryRequestAgent := &pb.QueryRangeRequest{
		Query: `parca_agent_cpu:samples:count:cpu:nanoseconds:delta`,
		Start: timestamppb.New(timestamp.Time(0)),
		End:   timestamppb.New(timestamp.Time(math.MaxInt64)),
		Limit: 10,
	}

	/*queryRequestAgentContainer := &pb.QueryRangeRequest{
		Query: `parca_agent_cpu:samples:count:cpu:nanoseconds:delta{container='parca-agent'}`,
		Start: timestamppb.New(timestamp.Time(1658899355228)),
		End:   timestamppb.New(timestamp.Time(1658900255228)),
		Limit: 10,
	}

	queryRequestServer := &pb.QueryRangeRequest{
		Query: `process_cpu:samples:count:cpu:nanoseconds:delta{container='parca'}`,
		Start: timestamppb.New(timestamp.Time(1658899355228)),
		End:   timestamppb.New(timestamp.Time(1658900255228)),
		Limit: 10,
	}
	*/

	//resp2, err2 := c.QueryRange(ctx, queryRequestAgentContainer)
	//resp3, err3 := c.QueryRange(ctx, queryRequestServer)

	for i := 0; i < 10; i++ {
		resp1, err1 := c.QueryRange(ctx, queryRequestAgent)

		if err1 != nil {
			status, ok := status.FromError(err1)
			if ok && status.Code() == codes.Unavailable {
				t.Log("query range api unavailable, retrying in a second")
				time.Sleep(time.Minute)
				continue
			}
			t.Fatal(err1)
		}

		//require.NoError(t, err1)
		require.NotEmpty(t, resp1.Series)
	}

	/* require.NoError(t, err1)
	 require.NotEmpty(t, resp1.Series)

	require.NoError(t, err2)
	require.NotEmpty(t, resp2.Series)

	require.NoError(t, err3)
	require.NotEmpty(t, resp3.Series)
	*/
}
