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
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Action represents the various actions available for AsyncProfiler.
type Action string

var validActions = []string{
	"start",
	"resume",
	"stop",
}

type ProfilerOptions map[string]string

type AsyncProfiler struct {
	jattachPath  string
	libasyncPath string
	pid          int
	action       Action
	options      ProfilerOptions
}

type ProfilerOption func(*AsyncProfiler)

func WithEventType(eventType string) ProfilerOption {
	return func(p *AsyncProfiler) {
		p.options["event"] = eventType
	}
}

func WithDuration(duration string) ProfilerOption {
	return func(p *AsyncProfiler) {
		p.options["duration"] = duration
	}
}

func WithOutputFile(outputFile string) ProfilerOption {
	return func(p *AsyncProfiler) {
		p.options["file"] = outputFile
	}
}

// TODO: Move this to profiler package
// NewAsyncProfiler initializes a new AsyncProfiler instance with the given paths, process ID, event type, and duration.
func NewAsyncProfiler(jattachPath, libasyncPath string, pid int, opts ...func(*AsyncProfiler)) *AsyncProfiler {
	profiler := &AsyncProfiler{
		jattachPath:  jattachPath,
		libasyncPath: libasyncPath,
		pid:          pid,
	}

	for _, opt := range opts {
		opt(profiler)
	}

	return profiler
}

func (p *AsyncProfiler) SetAction(action string, options ...ProfilerOptions) error {
	isValid := false
	for _, validAction := range validActions {
		if action == validAction {
			isValid = true
			break
		}
	}

	if !isValid {
		return fmt.Errorf("invalid action: %s", action)
	}
	p.action = Action(action)

	if len(options) > 0 {
		optionsSlice := []string{}
		for k, v := range options[0] {
			optionsSlice = append(optionsSlice, fmt.Sprintf("%s=%s", k, v))
		}
		optionsStr := strings.Join(optionsSlice, ",")
		p.action = Action(fmt.Sprintf("%s,%s", action, optionsStr))
	}

	return nil
}

// RunFdtransfer runs the fdtransfer command to start the fdtransfer
// server. Note that the client is part of the libasyncprofielr.so
// binary. The client connects to the fdtransfer server using a Unix
// domain socket and sends a request to the server for a
// file descriptor, specifying the type of the request (e.g.,
// PERF_FD for perf_event_open()). The server processes the request,
// opens the file descriptor, and sends it back to the client using
// Unix domain socket with ancillary data (SCM_RIGHTS). The client
// receives the file descriptor and can use it for further operations.
func RunFdtransfer(fdtransferPath string, pid int) error {
	cmdArgs := []string{
		fdtransferPath,
		strconv.Itoa(pid),
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start fdtransfer: %w", err)
	}

	// Use a goroutine to wait for the command to finish and handle errors
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("Error waiting for fdtransfer: %v", err)
		} else {
			log.Printf("fdtransfer completed successfully")
		}
	}()

	return nil
}

// BuildCommand builds the command to be executed to run AsyncProfiler.
func (p *AsyncProfiler) BuildCommand(ctx context.Context) (*exec.Cmd, error) {
	// Check if jattach and libasyncProfiler.so files exist
	if _, err := os.Stat(p.jattachPath); os.IsNotExist(err) {
		return nil, errors.New("jattach file not found")
	}

	if _, err := os.Stat(p.libasyncPath); os.IsNotExist(err) {
		return nil, errors.New("libasyncProfiler.so file not found")
	}

	args := []string{strconv.Itoa(p.pid), "load", p.libasyncPath, "true", string(p.action)}

	for key, value := range p.options {
		args = append(args, fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.CommandContext(ctx, p.jattachPath, args...) //nolint:gosec
	return cmd, nil
}
