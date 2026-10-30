// Copyright 2026 The Parca Authors
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

package reporter

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/internal/log"
)

type fakeLogsServer struct {
	plogotlp.UnimplementedGRPCServer
	mu   sync.Mutex
	logs []plog.Logs
}

func (s *fakeLogsServer) Export(_ context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := plog.NewLogs()
	req.Logs().CopyTo(l)
	s.logs = append(s.logs, l)
	return plogotlp.NewExportResponse(), nil
}

// TestSelfLogsReachRemoteStore runs the agent's log path end to end: slog,
// through log.ForOTLP and the otelslog bridge, into the reporter's
// LoggerProvider and out over gRPC as OTLP logs.
func TestSelfLogsReachRemoteStore(t *testing.T) {
	flags.RegisterProtoCodec()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	fake := &fakeLogsServer{}
	plogotlp.RegisterGRPCServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	lp, _, err := newProviders(Config{
		GRPCConn:       conn,
		ExportSelfLogs: true,
		AgentRevision:  "rev1",
		NodeName:       "node1",
		ExternalLabels: []Label{
			{Name: "parca.agent", Value: "true"},
			{Name: "service.name", Value: "other-service"},
			{Name: "host.name", Value: "other-host"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, lp)

	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	log.Setup(io.Discard, "logfmt", slog.LevelInfo)
	log.Tee(log.ForOTLP(otelslog.NewHandler("parca-agent.agent", otelslog.WithLoggerProvider(lp))))

	log.Infof("hello %d", 42)
	slog.Warn("structured", "pid", 7)
	slog.Info("local only", log.SkipOTLP)
	slog.Debug("below level")
	require.NoError(t, lp.ForceFlush(context.Background()))

	fake.mu.Lock()
	defer fake.mu.Unlock()
	var bodies []string
	for _, l := range fake.logs {
		rls := l.ResourceLogs()
		for i := range rls.Len() {
			rl := rls.At(i)
			require.Equal(t, map[string]any{
				"service.name":    "parca-agent",
				"service.version": "rev1",
				"host.name":       "node1",
				"parca.agent":     "true",
			}, subset(rl.Resource().Attributes().AsRaw(), "service.name", "service.version", "host.name", "parca.agent"))
			sls := rl.ScopeLogs()
			for j := range sls.Len() {
				require.Equal(t, "parca-agent.agent", sls.At(j).Scope().Name())
				lrs := sls.At(j).LogRecords()
				for k := range lrs.Len() {
					bodies = append(bodies, lrs.At(k).Body().Str())
				}
			}
		}
	}
	require.Equal(t, []string{"hello 42", "structured"}, bodies)
}

func subset(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}
