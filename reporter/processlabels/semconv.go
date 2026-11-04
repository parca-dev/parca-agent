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

package processlabels

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/otel/attribute"
)

// Resource attribute keys. They are spelled out rather than pulled from
// semconv, where a module bump could rename one silently.
const (
	AttrServiceName    = "service.name"
	AttrProcessPID     = "process.pid"
	AttrProcessExePath = "process.executable.path"
	AttrProcessExeName = "process.executable.name"
	AttrContainerID    = "container.id"
	AttrHostName       = "host.name"
	AttrK8sNodeName    = "k8s.node.name"

	// SchemaURL declares which convention version the keys above follow. It
	// matches what upstream's OTLP reporter stamps, and is spelled out for the
	// same reason the keys are.
	SchemaURL = "https://opentelemetry.io/schemas/1.37.0"
)

// Process is what PutProcessAttributes renders: a process's resolved labels
// plus the identity fields that don't come from labels.
type Process struct {
	Labels labels.Labels

	PID            int64
	ExecutablePath string
	ContainerID    string

	// ResourceAttrs is the profiler's resolved resource, including any
	// declared service.name. Do not merge it with raw environment variables.
	ResourceAttrs attribute.Set
}

// PutExternalAttributes adds configured string labels without replacing the
// resource's own identity or changing the types of existing attributes.
func PutExternalAttributes(attrs pcommon.Map, externalLabels map[string]string) {
	for name, value := range externalLabels {
		if _, exists := attrs.Get(name); !exists {
			attrs.PutStr(name, value)
		}
	}
}

// ExternalAttributes converts configured string labels for SDK resources.
// Append the resource's own attributes after these so its identity wins.
func ExternalAttributes(externalLabels map[string]string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(externalLabels))
	for name, value := range externalLabels {
		attrs = append(attrs, attribute.String(name, value))
	}
	return attrs
}

// PutHostAttributes sets the attributes identifying the node: host.name, and
// k8s.node.name on a cluster, where --node must match the Kubernetes node name
// and so holds for every process here, pod or not.
func PutHostAttributes(attrs pcommon.Map, nodeName string, inKubernetes bool) {
	if nodeName == "" {
		return
	}
	attrs.PutStr(AttrHostName, nodeName)
	if inKubernetes {
		attrs.PutStr(AttrK8sNodeName, nodeName)
	}
}

// PutProcessAttributes copies the profiler's resolved resource, then sets
// process and host identity and the provider/relabel labels. Explicit relabel
// rules still win. Like upstream, it does not synthesize a service.name.
func PutProcessAttributes(attrs pcommon.Map, p Process, nodeName string, inKubernetes bool) {
	for iter := p.ResourceAttrs.Iter(); iter.Next(); {
		kv := iter.Attribute()
		setAttributeValue(attrs.PutEmpty(string(kv.Key)), kv.Value)
	}
	if p.PID != 0 {
		attrs.PutInt(AttrProcessPID, p.PID)
	}
	if p.ExecutablePath != "" {
		attrs.PutStr(AttrProcessExePath, p.ExecutablePath)
		_, name := filepath.Split(p.ExecutablePath)
		attrs.PutStr(AttrProcessExeName, name)
	}
	if p.ContainerID != "" {
		attrs.PutStr(AttrContainerID, p.ContainerID)
	}
	PutHostAttributes(attrs, nodeName, inKubernetes)

	p.Labels.Range(func(l labels.Label) {
		switch l.Name {
		case "comm", "node":
			// comm is a process title, not executable identity. The node
			// already has host.name and, on Kubernetes, k8s.node.name.
			// Arrow and explicit relabel rules retain the original labels.
			return
		case "process.parent_pid":
			if pid, err := strconv.ParseInt(l.Value, 10, 64); err == nil {
				attrs.PutInt(l.Name, pid)
			}
		case "container.image.tags", "container.image.repo_digests":
			values := attrs.PutEmptySlice(l.Name)
			for _, value := range strings.Split(l.Value, ",") {
				values.AppendEmpty().SetStr(value)
			}
		default:
			attrs.PutStr(l.Name, l.Value)
		}
	})
}

// Mirrors upstream reporter/internal/pdata's conversion, including structured
// and empty values. That internal package cannot be imported by the agent.
func setAttributeValue(dst pcommon.Value, src attribute.Value) {
	switch src.Type() {
	case attribute.BOOL:
		dst.SetBool(src.AsBool())
	case attribute.INT64:
		dst.SetInt(src.AsInt64())
	case attribute.FLOAT64:
		dst.SetDouble(src.AsFloat64())
	case attribute.STRING:
		dst.SetStr(src.AsString())
	case attribute.BYTESLICE:
		dst.SetEmptyBytes().FromRaw(src.AsByteSlice())
	case attribute.BOOLSLICE:
		setSliceValue(dst, src.AsBoolSlice(), pcommon.Value.SetBool)
	case attribute.INT64SLICE:
		setSliceValue(dst, src.AsInt64Slice(), pcommon.Value.SetInt)
	case attribute.FLOAT64SLICE:
		setSliceValue(dst, src.AsFloat64Slice(), pcommon.Value.SetDouble)
	case attribute.STRINGSLICE:
		setSliceValue(dst, src.AsStringSlice(), pcommon.Value.SetStr)
	case attribute.SLICE:
		setSliceValue(dst, src.AsSlice(), setAttributeValue)
	case attribute.MAP:
		m := dst.SetEmptyMap()
		for _, kv := range src.AsMap() {
			setAttributeValue(m.PutEmpty(string(kv.Key)), kv.Value)
		}
	}
}

func setSliceValue[T any](dst pcommon.Value, values []T, set func(pcommon.Value, T)) {
	sl := dst.SetEmptySlice()
	sl.EnsureCapacity(len(values))
	for _, v := range values {
		set(sl.AppendEmpty(), v)
	}
}
