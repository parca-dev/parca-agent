package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOOMProfRoundTrip(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: must be run as root for cgroup operations")
	}

	// Skip if token file doesn't exist
	tokenFile := filepath.Join(os.Getenv("HOME"), "ps-token.txt")
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		t.Skipf("Skipping test: %s not found", tokenFile)
	}

	// Read the token for later use in querying
	tokenBytes, err := os.ReadFile(tokenFile)
	require.NoError(t, err)
	token := strings.TrimSpace(string(tokenBytes))

	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	// Generate unique test ID
	testID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Memory limit configuration
	memoryLimitMB := 500
	memoryLimitBytes := memoryLimitMB * 1024 * 1024

	// Set up cgroup v2 to limit memory
	cgroupName := fmt.Sprintf("parca-agent-test-%s", testID)
	cgroupPath := filepath.Join("/sys/fs/cgroup", cgroupName)
	err = os.Mkdir(cgroupPath, 0755)
	require.NoError(t, err)
	defer func() {
		// Clean up cgroup - first remove processes, then the directory
		os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte("0"), 0644)
		os.RemoveAll(cgroupPath)
	}()

	// Set memory limit
	memLimitFile := filepath.Join(cgroupPath, "memory.max")
	err = os.WriteFile(memLimitFile, []byte(fmt.Sprintf("%d", memoryLimitBytes)), 0644)
	require.NoError(t, err)
	t.Logf("Set memory limit to %dMB (%d bytes)", memoryLimitMB, memoryLimitBytes)

	// Disable swap to ensure OOM happens
	memSwapFile := filepath.Join(cgroupPath, "memory.swap.max")
	err = os.WriteFile(memSwapFile, []byte("0"), 0644)
	if err != nil {
		t.Logf("Warning: failed to set memory.swap.max: %v", err)
	}

	// Enable memory controller in parent if needed
	parentControl := filepath.Join("/sys/fs/cgroup", "cgroup.subtree_control")
	controlData, _ := os.ReadFile(parentControl)
	if !strings.Contains(string(controlData), "memory") {
		err = os.WriteFile(parentControl, []byte("+memory"), 0644)
		if err != nil {
			t.Logf("Warning: failed to enable memory controller in parent: %v", err)
		}
	}

	// We'll add the parca-agent process to the cgroup
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")

	// Build the command to run parca-agent
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Get the current working directory (should be parca-agent root)
	wd, err := os.Getwd()
	require.NoError(t, err)

	// Check if parca-agent binary exists, if not build it
	binaryPath := filepath.Join(wd, "parca-agent")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Log("Building parca-agent binary...")
		buildCmd := exec.Command("go", "build", "-o", "parca-agent", ".")
		buildCmd.Dir = wd
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build parca-agent: %v\nOutput: %s", err, buildOutput)
		}
	}

	// Create a wrapper script that adds itself to the cgroup before running parca-agent
	wrapperScript := `#!/bin/bash
set -e
echo "Adding PID $$ to cgroup..."
echo $$ > ` + procsFile + `
# Verify we're in the cgroup
cat /proc/$$/cgroup
# Check memory limit
echo "Memory limit:"
cat ` + memLimitFile + `
# Run the command as a separate process so we don't scan it as bash and decide its not a Go proc
"$@" &
echo "Spawned parca-agent: $!"
wait $!
`
	wrapperFile := filepath.Join(tmpDir, "cgroup-wrapper.sh")
	err = os.WriteFile(wrapperFile, []byte(wrapperScript), 0755)
	require.NoError(t, err)

	// Set GOMEMLIMIT env var to prevent automemlimit from adjusting based on cgroup
	cmd := exec.CommandContext(ctx, wrapperFile, binaryPath,
		//"--log-level=debug",
		"--node=oomprof-test-node",
		"--remote-store-address=grpc.polarsignals.com:443",
		fmt.Sprintf("--remote-store-bearer-token-file=%s", tokenFile),
		"--enable-oom-prof",
		fmt.Sprintf("--metadata-external-labels=test_id=%s", testID),
	)
	cmd.Env = append(os.Environ(), "GODEBUG=memprofilerate=1")
	cmd.Dir = wd

	// Capture output
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)

	// Start the process
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// Read output in background
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// Wait for parca-agent to start and then OOM
	t.Log("Waiting for parca-agent to start and eventually OOM...")

	// Wait for the agent process to exit (should be OOM killed)
	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	select {
	case err := <-cmdDone:
		t.Logf("parca-agent process exited with: %v", err)
		// The process should have been killed by OOM killer
		if err == nil {
			t.Fatal("parca-agent exited cleanly, expected OOM kill")
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("parca-agent did not OOM within 2 minutes")
	}

	// Wait for the OOM profile to be reported to backend
	t.Log("Waiting for OOM profile to be reported...")
	time.Sleep(30 * time.Second)

	// Query the polarsignals.com backend to verify OOM was reported
	t.Log("Querying polarsignals.com for OOM profile...")
	client := &http.Client{Timeout: 30 * time.Second}

	// Try multiple queries with different approaches
	found := false
	for attempt := 0; attempt < 3 && !found; attempt++ {
		if attempt > 0 {
			time.Sleep(10 * time.Second)
		}

		// Query for profiles with our test ID
		queryURL := "https://api.polarsignals.com/api/v1/query"
		query := fmt.Sprintf(`{node="oomprof-test-node",test_id="%s"}`, testID)

		req, err := http.NewRequest("GET", queryURL, nil)
		require.NoError(t, err)

		req.Header.Set("Authorization", "Bearer "+token)
		q := req.URL.Query()
		q.Add("query", query)
		q.Add("time", fmt.Sprintf("%d", time.Now().Unix()))
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("Query attempt %d failed: %v", attempt+1, err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		t.Logf("Query response (attempt %d): Status=%d, Body=%s", attempt+1, resp.StatusCode, string(body))

		if resp.StatusCode == http.StatusOK {
			// Parse response to check for actual data
			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err == nil {
				if data, ok := result["data"].(map[string]interface{}); ok {
					if resultData, ok := data["result"].([]interface{}); ok && len(resultData) > 0 {
						found = true
						t.Log("Successfully found OOM profile in backend!")
					}
				}
			}
		}
	}

	if !found {
		// Try one more time with a range query
		queryURL := "https://api.polarsignals.com/api/v1/query_range"
		req, err := http.NewRequest("GET", queryURL, nil)
		require.NoError(t, err)

		req.Header.Set("Authorization", "Bearer "+token)
		q := req.URL.Query()
		q.Add("query", fmt.Sprintf(`{node="oomprof-test-node",test_id="%s"}`, testID))
		q.Add("start", fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix()))
		q.Add("end", fmt.Sprintf("%d", time.Now().Unix()))
		q.Add("step", "30s")
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		t.Logf("Range query response: Status=%d, Body=%s", resp.StatusCode, string(body))

		require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to query backend")

		// Check if we got any results
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err == nil {
			if data, ok := result["data"].(map[string]interface{}); ok {
				if resultData, ok := data["result"].([]interface{}); ok && len(resultData) > 0 {
					found = true
				}
			}
		}
	}

	require.True(t, found, "OOM profile not found in polarsignals.com backend")
}
