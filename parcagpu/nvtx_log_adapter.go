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

package parcagpu

import (
	"context"
	"math"
	"strconv"
	"time"

	profilerreporter "go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
)

// NvtxLogScope is the instrumentation scope NVTX records are emitted under, so
// consumers can filter them from other agent log producers.
const NvtxLogScope = "parca-agent.nvtx"

// nvtxLogAdapter implements profilerreporter.LogReporter by translating each
// NVTX event into an OTel log.Record and emitting it via the agent's shared
// LoggerProvider (ParcaReporter.Logger).
//
// One record per NVTX event keeps the body a stable enumeration
// ("nvtx.range.push", "nvtx.mark", …) and pushes user-provided strings into
// attributes — easier to filter/aggregate downstream than overloading the body.
type nvtxLogAdapter struct {
	logger log.Logger
}

func newNvtxLogAdapter(logger log.Logger) *nvtxLogAdapter {
	return &nvtxLogAdapter{logger: logger}
}

// Compile-time check.
var _ profilerreporter.LogReporter = (*nvtxLogAdapter)(nil)

func (a *nvtxLogAdapter) ReportNvtxEvent(ev *samples.NvtxLogEvent) error {
	var rec log.Record
	rec.SetTimestamp(time.Unix(0, int64(ev.TimestampNs)))
	rec.SetObservedTimestamp(time.Now())
	body := nvtxBody(ev.Kind)
	rec.SetEventName(body)
	rec.SetBody(attribute.StringValue(body))
	rec.AddAttributes(
		attribute.Int64("process.pid", int64(ev.PID)),
		attribute.Int64("thread.id", int64(ev.TID)),
	)
	if ev.Message != "" {
		rec.AddAttributes(attribute.String("nvtx.message", ev.Message))
	}
	if ev.CorrelationID != 0 {
		rec.AddAttributes(attribute.Int64("cuda.correlation_id", int64(ev.CorrelationID)))
	}
	if ev.DeviceID != math.MaxUint32 {
		rec.AddAttributes(attribute.Int64("cuda.device_id", int64(ev.DeviceID)))
	}
	if ev.Color != 0 {
		// ARGB is mostly visual; carry it as a hex string so downstream
		// consumers can render it directly without re-encoding.
		rec.AddAttributes(attribute.String("nvtx.color", "0x"+strconv.FormatUint(uint64(ev.Color), 16)))
	}
	if ev.Payload != 0 {
		rec.AddAttributes(attribute.Int64("nvtx.payload", int64(ev.Payload)))
	}
	if ev.RangeID != 0 {
		rec.AddAttributes(attribute.Int64("nvtx.range_id", int64(ev.RangeID)))
	}
	a.logger.Emit(context.Background(), rec)
	return nil
}

// ReportNvtxResourceName emits a `nvtx.name.<resource>` log record. The agent
// could alternatively cache these and apply them as enrichment to subsequent
// NVTX events, but emitting as logs keeps the consumer model uniform and lets
// downstream tooling decide how to join.
func (a *nvtxLogAdapter) ReportNvtxResourceName(ev *samples.NvtxResourceNameEvent) error {
	now := time.Now()
	var rec log.Record
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	body := nvtxResourceBody(ev.Kind)
	rec.SetEventName(body)
	rec.SetBody(attribute.StringValue(body))
	rec.AddAttributes(
		attribute.Int64("process.pid", int64(ev.PID)),
		attribute.Int64("nvtx.resource.id", int64(ev.ID)),
		attribute.String("nvtx.resource.name", ev.Name),
	)
	a.logger.Emit(context.Background(), rec)
	return nil
}

func nvtxBody(k samples.NvtxKind) string {
	switch k {
	case samples.NvtxKindRangePush:
		return "nvtx.range.push"
	case samples.NvtxKindRangePop:
		return "nvtx.range.pop"
	case samples.NvtxKindRangeStart:
		return "nvtx.range.start"
	case samples.NvtxKindRangeEnd:
		return "nvtx.range.end"
	case samples.NvtxKindMark:
		return "nvtx.mark"
	default:
		return "nvtx.unknown"
	}
}

func nvtxResourceBody(k samples.NvtxResourceKind) string {
	switch k {
	case samples.NvtxResourceOSThread:
		return "nvtx.name.thread"
	case samples.NvtxResourceCUDAStream:
		return "nvtx.name.cuda_stream"
	case samples.NvtxResourceCUDADevice:
		return "nvtx.name.cuda_device"
	case samples.NvtxResourceCUDAKernel:
		return "nvtx.name.cuda_kernel"
	default:
		return "nvtx.name.unknown"
	}
}
