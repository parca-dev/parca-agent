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

//go:build nonvml

// This file provides a no-op Producer for builds that exclude NVML (the
// "nonvml" tag, used by the fully-static build). go-nvml requires cgo and a
// dynamically linked binary so it can dlopen libnvidia-ml at runtime; in a
// static binary that dlopen cannot resolve NVML symbols and crashes, so the
// static build is compiled without it. NewProducer reports GPU metrics as
// unavailable, and the caller disables them gracefully.
package gpumetrics

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

// Producer is a no-op stand-in used when built without NVML support.
type Producer struct{}

// NewProducer always reports that NVML GPU metrics are unavailable in this
// build. Use the default (dynamically linked) build for GPU metrics.
func NewProducer() (*Producer, error) {
	return nil, errors.New("parca-agent built without NVML GPU metrics support (static build); use the default dynamic build")
}

// SetLabelResolver is a no-op in the NVML-less build.
func (p *Producer) SetLabelResolver(LabelResolver) {}

// DeviceCount always reports zero devices in the NVML-less build.
func (p *Producer) DeviceCount() int { return 0 }

// Produce is a no-op in the NVML-less build.
func (p *Producer) Produce(pmetric.MetricSlice) error { return nil }

// Collect is a no-op in the NVML-less build.
func (p *Producer) Collect(context.Context) error { return nil }
