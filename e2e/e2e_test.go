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

package e2e

import (
	"context"
	"flag"
	"math"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/stretchr/testify/require"
	"github.com/zcalusic/sysinfo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	pb "github.com/parca-dev/parca/gen/proto/go/parca/query/v1alpha1"
)

var kubecontext = flag.String("context", "", "The name of the kubeconfig context to use")

// Checks for parca-server and parca-agent pods and returns pod names if true
// Returns empty string if no pods are found.
func CheckPodsExist(t *testing.T, ctx context.Context, kubeClient kubernetes.Interface) (string, string) {
	t.Helper()

	labelSelectorParcaServer := labels.FormatLabels(map[string]string{"app.kubernetes.io/name": "parca"})
	labelSelectorParcaAgent := labels.FormatLabels(map[string]string{"app.kubernetes.io/name": "parca-agent"})

	parcaServerPod, err := kubeClient.CoreV1().Pods("parca").List(ctx, metav1.ListOptions{LabelSelector: labelSelectorParcaServer})
	require.NoErrorf(t, err, "Unable to fetch pods in parca namespace: %w", err)

	parcaAgentPod, err := kubeClient.CoreV1().Pods("parca").List(ctx, metav1.ListOptions{LabelSelector: labelSelectorParcaAgent})
	require.NoErrorf(t, err, "Unable to fetch pods in parca namespace: %w", err)

	if len(parcaServerPod.Items) == 0 {
		t.Log("Parca Server Pod not found")
		return "", ""
	}

	if len(parcaAgentPod.Items) == 0 {
		t.Log("Parca Agent Pod not found")
		return "", ""
	}

	return parcaServerPod.Items[0].Name, parcaAgentPod.Items[0].Name
}

// TODO(sylfrena): Cleanup logs once e2e tests are stabilized
// TODO(sylfrena): Reduce context timeouts
// TODO(sylfrena): Use exponential backoff instead.
func TestGRPCIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var si sysinfo.SysInfo
	si.GetSysInfo()

	t.Log("Running on kernel", si.Kernel.Release)

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: *kubecontext},
	)
	cfg, err := kubeConfig.ClientConfig()
	require.NoError(t, err)

	kubeClient, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)

	parcaServer, parcaAgent := CheckPodsExist(t, ctx, kubeClient)
	t.Log("Pods discovered: ", parcaServer, parcaAgent)

	ns := "parca"

	serverCloser, err := StartPortForward(ctx, cfg, "https", parcaServer, ns, "7070")
	if err != nil {
		require.NoError(t, err, "failed to start port forwarding Parca Server: %v", err)
	}
	defer serverCloser()

	// If port-forwarding the agent, the port TCP/7071 may already
	// be in used on the host by docker-proxy (e.g. Minikube with none driver),
	// ensure to use a different local port (e.g. "7072:7071")

	t.Log("Starting tests")
	conn, err := grpc.Dial("127.0.0.1:7070", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	t.Log("Creating query service client")
	c := pb.NewQueryServiceClient(conn)

	t.Log("Performing Query Range Request")
	queryRequestAgent := &pb.QueryRangeRequest{
		Query: `parca_agent_cpu:samples:count:cpu:nanoseconds:delta`,
		Start: timestamppb.New(timestamp.Time(0)),
		End:   timestamppb.New(timestamp.Time(math.MaxInt64)),
		Limit: 10,
	}

	for i := 0; i < 10; i++ {
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		resp, err := c.QueryRange(ctx, queryRequestAgent)
		if err != nil {
			status, ok := status.FromError(err)
			if ok && status.Code() == codes.Unavailable {
				t.Log("query range api unavailable, retrying in a second")
				time.Sleep(time.Second)
				continue
			}
			if ok && status.Code() == codes.NotFound {
				t.Log("query range resource not found, retrying in a minute", err)
				time.Sleep(time.Second)
				continue
			}
			if ok && status.Code() == codes.DeadlineExceeded {
				t.Log("deadline exceeded", err)
				time.Sleep(time.Second)
				continue
			}
			t.Error(err)
		}

		require.NotEmpty(t, resp.Series)
	}
}
