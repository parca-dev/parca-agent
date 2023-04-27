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

package asyncprofiler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/asyncprofiler"
	"github.com/parca-dev/parca-agent/pkg/convert"
)

func TestIntegrationAsyncProfiler(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Start the Java program
	javaProgramPath := filepath.Join(cwd, "testdata", "java-app", "target", "spring-0.0.1-SNAPSHOT.jar")
	cmd := exec.Command("java", "-Xms1G", "-Xmx1G", "-XX:+AlwaysPreTouch", "-jar", javaProgramPath)
	err = cmd.Start()
	require.NoError(t, err, "Failed to start Java program")

	time.Sleep(30 * time.Second) // We need to wait for the Java program to start
	// Get the Java process PID
	javaPID := cmd.Process.Pid

	// Initialize AsyncProfiler with required parameters
	profiler := asyncprofiler.NewAsyncProfiler(
		filepath.Join(cwd, "testdata", "jattach"),
		filepath.Join(cwd, "testdata", "libasyncProfiler.so"),
		javaPID,
	)

	// Run fdtransfer
	err = asyncprofiler.RunFdtransfer(filepath.Join(cwd, "testdata", "fdtransfer"), javaPID)
	require.NoError(t, err, "Failed to run fdtransfer")

	time.Sleep(10 * time.Second) // We need to wait for fdtransfer to finish loading

	// Set action to start
	err = profiler.SetAction("start", asyncprofiler.ProfilerOptions{
		"event": "cpu",
		"file":  "prof.jfr",
	})
	require.NoError(t, err, "Failed to set action")

	// Construct the start command
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	profilerCmd, err := profiler.BuildCommand(ctx)
	require.NoError(t, err, "Failed to build command")

	// Execute the start command
	err = profilerCmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Start command error: %v\n", err)
	}
	require.NoError(t, err, "Failed to run command")

	// Sleep for the specified duration
	time.Sleep(120 * time.Second)

	// Set action to stop
	err = profiler.SetAction("stop")
	require.NoError(t, err, "Failed to set action")

	// Construct the stop command
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	profilerCmd, err = profiler.BuildCommand(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Stop command error: %v\n", err)
	}
	require.NoError(t, err, "Failed to build command")

	// Execute the stop command
	err = profilerCmd.Run()
	require.NoError(t, err, "Failed to run command")

	// Check the exit code
	require.Equal(t, 0, profilerCmd.ProcessState.ExitCode(), "Non-zero exit code")

	// Check if the output file "prof.jfr" exists
	_, err = os.Stat("prof.jfr")
	require.NoError(t, err, "Failed to find output file")

	jfrFile, err := os.Open("prof.jfr")
	require.NoError(t, err, "Failed to open JFR file")
	defer jfrFile.Close()

	pprofProfile, err := convert.JfrToPprof(jfrFile)
	require.NoError(t, err, "Failed to convert JFR to pprof")
	require.NotNil(t, pprofProfile, "Pprof profile is nil")

	// Save the converted pprof profile to a file
	pprofFile, err := os.Create("prof.pprof")
	require.NoError(t, err, "Failed to create pprof file")
	defer pprofFile.Close()

	err = pprofProfile.Write(pprofFile)
	require.NoError(t, err, "Failed to write pprof profile")

	// Clean up the output files
	outputFiles := []string{"prof.jfr", "prof.pprof"}

	for _, outputFile := range outputFiles {
		err = os.Remove(outputFile)
		require.NoError(t, err, fmt.Sprintf("Failed to remove output file: %s", outputFile))
	}

	// Terminate the Java program
	process := cmd.Process
	err = process.Signal(syscall.SIGKILL)
	require.NoError(t, err, "Failed to terminate Java program")
}
