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

package reporter

import (
	"strconv"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// sampleLabelSpec is the single source of truth for the labels that vary per
// sample rather than per process. Everything about one of them lives on its
// row: the Prometheus name both arrow backends write, the OTLP attribute the
// pprofile builder emits instead, and whether that attribute is typed as an
// integer.
//
// Adding a per-sample label is one row here plus a case in
// sampleLabeler.build; nothing downstream needs to learn its name.
type sampleLabelSpec struct {
	// name is the Prometheus label name. The arrow writers use it verbatim
	// as a column name, and relabel configs match on it.
	name string
	// attr is the OTLP attribute key the OTLP backend emits instead.
	attr string
	// isInt marks an attribute semconv types as an integer. Emitting those
	// as strings is not cosmetic: a consumer that reads thread.id as an int
	// either errors or drops the attribute.
	isInt bool
}

var sampleLabelSpecs = [...]sampleLabelSpec{
	{name: "cpu", attr: attrCPUNumber, isInt: true},
	{name: "thread_id", attr: attrThreadID, isInt: true},
	{name: "thread_name", attr: attrThreadName},
}

// sampleLabelSpecByName indexes sampleLabelSpecs for the OTLP builder, which
// sees a finished label set rather than the fields it was built from -- a
// per-sample relabel pass can rewrite the values, so the attribute mapping has
// to work from names.
var sampleLabelSpecByName = func() map[string]sampleLabelSpec {
	m := make(map[string]sampleLabelSpec, len(sampleLabelSpecs))
	for _, s := range sampleLabelSpecs {
		m[s.name] = s
	}
	return m
}()

// sampleLabeler builds the per-sample half of a sample's attribution: the
// labels that change from sample to sample within one process, and so cannot
// come from the per-PID metadata providers or ride in processLabeler's cache.
//
// Every backend shares it. The arrow writers flatten its output into label
// columns; the OTLP builder maps it onto Sample attributes through the specs
// above. Keeping construction and mapping in one place is what stops the two
// from drifting.
//
// These labels are not subject to relabelling on the CPU/off-CPU/memory/GPU
// paths: they are patched on after processLabeler's cached relabel pass has
// already run. Probe samples are the exception -- see processLabeler.
type sampleLabeler struct {
	disableCPU        bool
	disableThreadID   bool
	disableThreadComm bool
}

func newSampleLabeler(cfg labelerConfig) sampleLabeler {
	return sampleLabeler{
		disableCPU:        cfg.DisableCPULabel,
		disableThreadID:   cfg.DisableThreadIDLabel,
		disableThreadComm: cfg.DisableThreadCommLabel,
	}
}

// enabled reports whether any per-sample label is turned on. When none are, a
// caller with nothing else to do can ship the cached process labels as-is.
func (s sampleLabeler) enabled() bool {
	return !s.disableCPU || !s.disableThreadID || !s.disableThreadComm
}

// build returns the per-sample labels for one sample, sorted.
func (s sampleLabeler) build(tid libpf.PID, comm libpf.Comm, cpu uint32) labels.Labels {
	sb := labels.NewScratchBuilder(len(sampleLabelSpecs))
	if !s.disableCPU {
		sb.Add("cpu", strconv.FormatUint(uint64(cpu), 10))
	}
	if !s.disableThreadID {
		sb.Add("thread_id", strconv.FormatUint(uint64(tid), 10))
	}
	if !s.disableThreadComm {
		sb.Add("thread_name", comm.String())
	}
	sb.Sort()
	return sb.Labels()
}

// split takes a flat label set that has been through a per-sample relabel pass
// and separates the per-sample labels back out from the process-invariant
// ones. A rule that renames one of them leaves it in the resource set, which
// keeps it on the profile rather than dropping it.
func (s sampleLabeler) split(merged labels.Labels) (resource, sample labels.Labels) {
	rb := labels.NewBuilder(merged)
	sb := labels.NewScratchBuilder(len(sampleLabelSpecs))
	for _, spec := range sampleLabelSpecs {
		if v := merged.Get(spec.name); v != "" {
			sb.Add(spec.name, v)
			rb.Del(spec.name)
		}
	}
	sb.Sort()
	return rb.Labels(), sb.Labels()
}
