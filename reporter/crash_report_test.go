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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/flags"
)

func TestSendCrashReport(t *testing.T) {
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

	stderr := "panic: boom\n\ngoroutine 1 [running]:\nmain.main()\n"
	require.NoError(t, SendCrashReport(context.Background(), conn, CrashReport{
		Stderr:         stderr,
		Status:         "exit status 2",
		ExitCode:       2,
		PID:            1234,
		ServiceVersion: "rev1",
		HostName:       "node1",
		HostArch:       "arm64",
		KernelRelease:  "6.12.0",
		ExternalLabels: map[string]string{"parca.agent": "true"},
	}))

	fake.mu.Lock()
	defer fake.mu.Unlock()
	require.Len(t, fake.logs, 1)
	rls := fake.logs[0].ResourceLogs()
	require.Equal(t, 1, rls.Len())
	require.Equal(t, map[string]any{
		"service.name":    "parca-agent",
		"service.version": "rev1",
		"host.name":       "node1",
		"parca.agent":     "true",
	}, subset(rls.At(0).Resource().Attributes().AsRaw(), "service.name", "service.version", "host.name", "parca.agent"))

	sl := rls.At(0).ScopeLogs()
	require.Equal(t, 1, sl.Len())
	require.Equal(t, "parca-agent.supervisor", sl.At(0).Scope().Name())
	lrs := sl.At(0).LogRecords()
	require.Equal(t, 1, lrs.Len())
	lr := lrs.At(0)
	require.Equal(t, plog.SeverityNumberFatal, lr.SeverityNumber())
	require.Equal(t, "parca_agent.crash", lr.EventName())
	require.Equal(t, "parca-agent exited abnormally (exit status 2)\n\n"+stderr, lr.Body().Str())
	require.Equal(t, map[string]any{
		"process.exit.code": int64(2),
		"process.pid":       int64(1234),
		"host.arch":         "arm64",
		"os.version":        "6.12.0",
	}, lr.Attributes().AsRaw())
}

func TestSendCrashReportUnimplemented(t *testing.T) {
	flags.RegisterProtoCodec()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer() // no logs service registered
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.Error(t, SendCrashReport(context.Background(), conn, CrashReport{Stderr: "x"}))
}
