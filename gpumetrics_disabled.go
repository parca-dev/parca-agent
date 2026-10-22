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

//go:build !gpumetrics

package main

import (
	"context"

	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/internal/log"

	"github.com/parca-dev/parca-agent/flags"
	"github.com/parca-dev/parca-agent/gpumetrics"
	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// startGPUMetrics only points out GPUs this build can't report on: NVML needs
// a dynamically linked binary, so the static build leaves GPU metrics out.
func startGPUMetrics(_ context.Context, _ flags.Flags, _ *grpc.ClientConn,
	_ *processlabels.Resolver, _ gpumetrics.DeclaredLookup,
) {
	if n := gpumetrics.CountNVIDIAGPUs("/proc"); n > 0 {
		log.Infof("Found %d NVIDIA GPU(s), but this parca-agent was built without GPU metrics (build tag gpumetrics)", n)
	}
}
