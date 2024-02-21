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

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/asyncprofiler"
	"github.com/parca-dev/parca-agent/pkg/convert"
)

func TestIntegrationAsyncProfiler(t *testing.T) {
	// Get current working directory
	cwd, err := os.Getwd()
	require.NoError(t, err)
	// Run the download script to get async-profiler artifacts
	scriptPath := filepath.Join(cwd, "../../scripts/download-async-profiler.sh")
	setupCmd := exec.Command("bash", scriptPath)
	err = setupCmd.Run()
	require.NoError(t, err, fmt.Sprintf("Failed to run the setup script: %s", scriptPath))

	asyncProfilerDir := filepath.Join(cwd, "goreleaser/dist/async-profiler/x64/libc")

	// Start the Java program
	javaProgramPath := filepath.Join(cwd, "testdata", "java-app", "demo-0.0.1-SNAPSHOT.jar")
	cmd := exec.Command("java", "-Xms1G", "-Xmx1G", "-XX:+AlwaysPreTouch", "-jar", javaProgramPath)
	fmt.Fprintf(os.Stdout, "Executing command: %v\n", cmd)
	err = cmd.Start()
	require.NoError(t, err, "Failed to start Java program")

	// Get the Java process PID
	javaPID := cmd.Process.Pid
	fmt.Fprintf(os.Stdout, "Java PID: %d\n", javaPID)

	// Wait until the Java application is properly running
	// TODO: Use a better way to check if Java app has started correctly
	time.Sleep(10 * time.Second)

	// Initialize AsyncProfiler with required parameters
	profiler := asyncprofiler.NewAsyncProfiler(
		filepath.Join(asyncProfilerDir, "jattach"),
		filepath.Join(asyncProfilerDir, "libasyncProfiler.so"),
		javaPID,
	)

	jfrOutputFile := filepath.Join(cwd, "prof.jfr")
	// Set action to start
	err = profiler.SetAction("start", asyncprofiler.ProfilerOptions{
		"event": "cpu",
		"file":  jfrOutputFile,
	})
	require.NoError(t, err, "Failed to set action")

	// Construct the start command
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	profilerCmd, err := profiler.BuildCommand(ctx)
	require.NoError(t, err, "Failed to build command")

	// Execute the start command
	var outbuf, errbuf bytes.Buffer
	profilerCmd.Stdout = &outbuf
	profilerCmd.Stderr = &errbuf
	fmt.Fprintf(os.Stdout, "Executing command: %v\n", profilerCmd)
	if err = profilerCmd.Run(); err != nil {
		err = fmt.Errorf("Failed to execute profiler: %w: %s: %s", err, outbuf.String(), errbuf.String())
	}
	require.NoError(t, err, "Failed to run start command")

	// Sleep for 120 seconds to collect the profile
	// TODO: Exercise 'duration' option from async-profiler here
	time.Sleep(120 * time.Second)

	// Set action to stop
	err = profiler.SetAction("stop")
	require.NoError(t, err, "Failed to set action")

	// Construct the stop command
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	profilerCmd, err = profiler.BuildCommand(ctx)
	require.NoError(t, err, "Failed to build command")

	// Execute the stop command
	fmt.Fprintf(os.Stdout, "Executing command: %v\n", profilerCmd)
	err = profilerCmd.Run()
	require.NoError(t, err, "Failed to run stop command")

	// Check the exit code
	require.Equal(t, 0, profilerCmd.ProcessState.ExitCode(), "Non-zero exit code")

	// Check if the output file "prof.jfr" exists
	_, err = os.Stat(jfrOutputFile)
	require.NoError(t, err, "Failed to find output file")

	jfrFile, err := os.Open(jfrOutputFile)
	require.NoError(t, err, "Failed to open JFR file")
	defer jfrFile.Close()

	pprofProfile, err := convert.JfrToPprof(jfrFile)
	require.NoError(t, err, "Failed to convert JFR to pprof")
	require.NotNil(t, pprofProfile, "Pprof profile is nil")

	// Ensure the Java program is terminated when this function ends.
	defer func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Errorf("Error while trying to terminate Java program: %v", err)
		}

		// Delete the JFR file.
		if err := os.Remove(jfrOutputFile); err != nil {
			t.Errorf("Error while trying to delete JFR file: %v", err)
		}
	}()
}
