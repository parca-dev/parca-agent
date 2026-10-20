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

package gpumetrics

import (
	"context"
	"maps"
	"slices"
	"sync"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// Collector gathers GPU metrics into a Producer until ctx is cancelled.
type Collector interface {
	Collect(ctx context.Context, rec *Producer) error
}

// Producer implements metricexport.Producer for GPU metrics. Its Collector
// records into per-resource buffers; Produce drains them.
type Producer struct {
	collector Collector
	processes ProcessResourcer

	mu    sync.Mutex
	host  *MetricBuffer
	procs map[uint32]*MetricBuffer
}

// NewProducer returns a Producer whose metrics come from c.
func NewProducer(c Collector) *Producer {
	return &Producer{
		collector: c,
		host:      newMetricBuffer(),
		procs:     map[uint32]*MetricBuffer{},
	}
}

// Collect runs the Collector until ctx is cancelled.
func (p *Producer) Collect(ctx context.Context) error {
	return p.collector.Collect(ctx, p)
}

// SetProcessResourcer sets how per-process metrics get their resource. Call
// before Collect starts. Without one, a process's resource carries only
// process.pid.
func (p *Producer) SetProcessResourcer(r ProcessResourcer) { p.processes = r }

// RecordHost appends to the host resource's metrics.
func (p *Producer) RecordHost(fn func(*MetricBuffer)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p.host)
}

// RecordProcess appends to the metrics of pid's resource.
func (p *Producer) RecordProcess(pid uint32, fn func(*MetricBuffer)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.procs[pid]
	if !ok {
		b = newMetricBuffer()
		p.procs[pid] = b
	}
	fn(b)
}

// Produce moves the metrics collected so far into host, and appends one
// ResourceMetrics per process that used a GPU since the last call.
func (p *Producer) Produce(host pmetric.MetricSlice, resources pmetric.ResourceMetricsSlice) error {
	p.mu.Lock()
	hostBuf, procs := p.host, p.procs
	p.host, p.procs = newMetricBuffer(), map[uint32]*MetricBuffer{}
	p.mu.Unlock()

	hostBuf.moveTo(host)

	for _, pid := range slices.Sorted(maps.Keys(procs)) {
		attrs := pcommon.NewMap()
		if p.processes == nil {
			attrs.PutInt(processlabels.AttrProcessPID, int64(pid))
		} else if !p.processes.PutResource(pid, attrs) {
			continue
		}

		rm := resources.AppendEmpty()
		rm.SetSchemaUrl(processlabels.SchemaURL)
		attrs.MoveTo(rm.Resource().Attributes())
		sm := rm.ScopeMetrics().AppendEmpty()
		sm.SetSchemaUrl(processlabels.SchemaURL)
		sm.Scope().SetName(ScopeName)
		procs[pid].moveTo(sm.Metrics())
	}
	return nil
}
