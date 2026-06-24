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

// Package supervisor detects NVIDIA GPUs and runs the gpu-metrics-agent binary
// as a supervised subprocess.
//
// NVML collection lives in a separate, dynamically linked binary because
// go-nvml must dlopen libnvidia-ml, which a fully-static parca-agent cannot
// do. This package is pure Go (no cgo, no NVML) so the static parca-agent can
// import it; it must never import the parent gpumetrics package.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/parca-dev/parca-agent/flags"
)

// ExitCodeUnavailable is the exit status gpu-metrics-agent uses when NVML
// can't be initialized or reports no devices. The supervisor treats it as
// permanent and does not restart the subprocess.
const ExitCodeUnavailable = 3

// BinaryName is the gpu-metrics-agent executable's file name. By default the
// supervisor looks for it next to the parca-agent executable.
const BinaryName = "gpu-metrics-agent"

const (
	minBackoff = 5 * time.Second
	maxBackoff = 5 * time.Minute
	// A subprocess that stayed up at least this long is considered healthy,
	// so its next crash restarts from minBackoff.
	healthyRuntime = 10 * time.Minute
	// How long to wait after SIGTERM before SIGKILLing the subprocess.
	stopTimeout = 10 * time.Second
)

// Config is everything needed to launch gpu-metrics-agent.
type Config struct {
	Binary         string
	Node           string
	ExportInterval time.Duration
	Log            flags.FlagsLogs
	RemoteStore    flags.FlagsRemoteStore
}

// CountNVIDIAGPUs counts the GPUs the NVIDIA kernel driver has bound, one
// directory per GPU under <procRoot>/driver/nvidia/gpus. This needs neither
// NVML nor /dev/nvidia* in the container, only a loaded driver, which NVML
// requires anyway.
func CountNVIDIAGPUs(procRoot string) int {
	entries, err := os.ReadDir(filepath.Join(procRoot, "driver", "nvidia", "gpus"))
	if err != nil {
		return 0
	}
	return len(entries)
}

// ResolveBinary returns the gpu-metrics-agent path to execute: bin if set,
// otherwise BinaryName next to the running executable.
func ResolveBinary(bin string) (string, error) {
	if bin == "" {
		self, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate parca-agent executable: %w", err)
		}
		bin = filepath.Join(filepath.Dir(self), BinaryName)
	}
	if _, err := os.Stat(bin); err != nil {
		return "", err
	}
	return bin, nil
}

// Run launches gpu-metrics-agent and restarts it with exponential backoff
// whenever it exits, until ctx is cancelled or it reports that GPU metrics are
// unavailable on this node.
func Run(ctx context.Context, cfg Config) {
	backoff := minBackoff
	for {
		start := time.Now()
		err := runOnce(ctx, cfg)
		if ctx.Err() != nil {
			return
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == ExitCodeUnavailable {
			log.Warn("gpu-metrics-agent reports GPU metrics unavailable on this node; not restarting")
			return
		}
		if time.Since(start) >= healthyRuntime {
			backoff = minBackoff
		}
		log.WithError(err).WithField("restart_in", backoff).Warn("gpu-metrics-agent exited")

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func runOnce(ctx context.Context, cfg Config) error {
	// Pdeathsig fires when the OS thread that forked the child exits, not the
	// process, so pin this goroutine to its thread for the child's lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.CommandContext(ctx, cfg.Binary, Args(cfg)...)
	cmd.Env = Env(cfg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopTimeout

	if err := cmd.Start(); err != nil {
		return err
	}
	log.WithField("pid", cmd.Process.Pid).Info("started gpu-metrics-agent")
	return cmd.Wait()
}

// Args renders cfg as gpu-metrics-agent command-line flags. The bearer token
// is deliberately omitted; Env passes it so it doesn't show up in the
// process's cmdline.
func Args(cfg Config) []string {
	rs := cfg.RemoteStore
	args := []string{
		"--node=" + cfg.Node,
		"--export-interval=" + cfg.ExportInterval.String(),
		"--log-level=" + cfg.Log.Level,
		"--log-format=" + cfg.Log.Format,
		"--remote-store-address=" + rs.Address,
		"--remote-store-grpc-max-call-recv-msg-size=" + strconv.Itoa(rs.GRPCMaxCallRecvMsgSize),
		"--remote-store-grpc-max-call-send-msg-size=" + strconv.Itoa(rs.GRPCMaxCallSendMsgSize),
		"--remote-store-grpc-startup-backoff-time=" + rs.GRPCStartupBackoffTime.String(),
		"--remote-store-grpc-connection-timeout=" + rs.GRPCConnectionTimeout.String(),
		"--remote-store-grpc-max-connection-retries=" + strconv.FormatUint(uint64(rs.GRPCMaxConnectionRetries), 10),
	}
	if rs.Insecure {
		args = append(args, "--remote-store-insecure")
	}
	if rs.InsecureSkipVerify {
		args = append(args, "--remote-store-insecure-skip-verify")
	}
	if rs.BearerTokenFile != "" {
		args = append(args, "--remote-store-bearer-token-file="+rs.BearerTokenFile)
	}
	if rs.ClientCert != "" {
		args = append(args, "--remote-store-client-cert="+rs.ClientCert)
	}
	if rs.ClientKey != "" {
		args = append(args, "--remote-store-client-key="+rs.ClientKey)
	}
	for k, v := range rs.GRPCHeaders {
		args = append(args, "--remote-store-grpc-headers="+k+"="+v)
	}
	return args
}

// Env returns the subprocess environment: parca-agent's own (so in-cluster
// Kubernetes config reaches the child's pod-label enrichment) with the bearer
// token set from cfg, since it may have come from a flag rather than the
// environment.
func Env(cfg Config) []string {
	env := os.Environ()
	if cfg.RemoteStore.BearerToken != "" {
		env = append(env, "PARCA_BEARER_TOKEN="+cfg.RemoteStore.BearerToken)
	}
	return env
}
