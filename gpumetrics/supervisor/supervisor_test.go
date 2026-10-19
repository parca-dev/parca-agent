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

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/flags"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestCountNVIDIAGPUs(t *testing.T) {
	root := t.TempDir()
	require.Equal(t, 0, CountNVIDIAGPUs(root), "no driver loaded")

	for _, bus := range []string{"0000:01:00.0", "0000:02:00.0"} {
		writeFile(t, filepath.Join(root, "driver/nvidia/gpus", bus, "information"), "")
	}
	require.Equal(t, 2, CountNVIDIAGPUs(root))
}

// TestArgsRoundTrip parses Args with the same flag structs gpu-metrics-agent
// uses, so a renamed or newly required remote-store flag breaks here rather
// than at runtime.
func TestArgsRoundTrip(t *testing.T) {
	in := Config{
		Node:           "gpu-node-1",
		ConfigPath:     "/etc/parca-agent/config.yaml",
		LabelTTL:       7 * time.Minute,
		ExportInterval: 15 * time.Second,
		Log:            flags.FlagsLogs{Level: "debug", Format: "json"},
		RemoteStore: flags.FlagsRemoteStore{
			Address:                  "grpc.example.com:443",
			BearerToken:              "secret-token",
			BearerTokenFile:          "/var/run/secrets/token",
			InsecureSkipVerify:       true,
			GRPCMaxCallRecvMsgSize:   1 << 20,
			GRPCMaxCallSendMsgSize:   2 << 20,
			GRPCStartupBackoffTime:   30 * time.Second,
			GRPCConnectionTimeout:    7 * time.Second,
			GRPCMaxConnectionRetries: 9,
			GRPCHeaders:              map[string]string{"x-scope-orgid": "tenant-a", "x-other": "a=b"},
			ClientCert:               "/certs/tls.crt",
			ClientKey:                "/certs/tls.key",
		},
	}

	// Mirrors cliFlags in cmd/gpu-metrics-agent.
	var out struct {
		Log            flags.FlagsLogs        `embed:"" prefix:"log-"`
		Node           string                 `default:"${hostname}"`
		ConfigPath     string                 `default:""`
		LabelTTL       time.Duration          `default:"10m"`
		ExportInterval time.Duration          `default:"10s"`
		RemoteStore    flags.FlagsRemoteStore `embed:"" prefix:"remote-store-"`
	}
	t.Setenv("PARCA_BEARER_TOKEN", "")
	for _, kv := range Env(in) {
		if v, ok := strings.CutPrefix(kv, "PARCA_BEARER_TOKEN="); ok {
			t.Setenv("PARCA_BEARER_TOKEN", v)
		}
	}
	parser, err := kong.New(&out, kong.Vars{"hostname": "unused"})
	require.NoError(t, err)
	args := Args(in)
	_, err = parser.Parse(args)
	require.NoError(t, err)

	for _, a := range args {
		require.NotContains(t, a, "secret-token", "bearer token must not appear in argv")
	}
	require.Equal(t, in.Node, out.Node)
	require.Equal(t, in.ConfigPath, out.ConfigPath)
	require.Equal(t, in.LabelTTL, out.LabelTTL)
	require.Equal(t, in.ExportInterval, out.ExportInterval)
	require.Equal(t, in.Log, out.Log)

	want := in.RemoteStore
	got := out.RemoteStore
	require.Equal(t, want.Address, got.Address)
	require.Equal(t, want.BearerToken, got.BearerToken)
	require.Equal(t, want.BearerTokenFile, got.BearerTokenFile)
	require.Equal(t, want.Insecure, got.Insecure)
	require.Equal(t, want.InsecureSkipVerify, got.InsecureSkipVerify)
	require.Equal(t, want.GRPCMaxCallRecvMsgSize, got.GRPCMaxCallRecvMsgSize)
	require.Equal(t, want.GRPCMaxCallSendMsgSize, got.GRPCMaxCallSendMsgSize)
	require.Equal(t, want.GRPCStartupBackoffTime, got.GRPCStartupBackoffTime)
	require.Equal(t, want.GRPCConnectionTimeout, got.GRPCConnectionTimeout)
	require.Equal(t, want.GRPCMaxConnectionRetries, got.GRPCMaxConnectionRetries)
	require.Equal(t, want.GRPCHeaders, got.GRPCHeaders)
	require.Equal(t, want.ClientCert, got.ClientCert)
	require.Equal(t, want.ClientKey, got.ClientKey)
}

func fakeBinary(t *testing.T, script string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), BinaryName)
	writeFile(t, bin, "#!/bin/sh\n"+script+"\n")
	require.NoError(t, os.Chmod(bin, 0o755))
	return bin
}

func TestRunStopsWhenUnavailable(t *testing.T) {
	cfg := Config{Binary: fakeBinary(t, "exit 3")}
	done := make(chan struct{})
	go func() {
		Run(t.Context(), cfg)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept restarting a subprocess that reported GPU metrics unavailable")
	}
}

func TestRunStopsSubprocessOnCancel(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "terminated")
	cfg := Config{Binary: fakeBinary(t, "trap 'touch "+marker+"; exit 0' TERM\nwhile :; do sleep 0.05; done")}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		Run(ctx, cfg)
		close(done)
	}()
	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(stopTimeout + 5*time.Second):
		t.Fatal("Run did not return after cancel")
	}
	require.FileExists(t, marker, "subprocess should receive SIGTERM on cancel")
}
