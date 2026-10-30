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
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"
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

// labelAttrs maps the parca-agent labels that have a semconv equivalent onto
// that key; an empty key drops the label. Only OTLP output renames them; the
// arrow backends keep parca-agent's vocabulary, which queries and relabel
// rules depend on.
var labelAttrs = map[string]string{
	// comm is the executable's base name truncated to 15 bytes, which is
	// what upstream's OTLP reporter emits under this key too.
	"comm": AttrProcessExeName,
	// node is --node, which host.name (and k8s.node.name on a cluster)
	// already carry.
	"node": "",
}

// Process is what PutProcessAttributes renders: a process's resolved labels
// plus the identity fields that don't come from labels.
type Process struct {
	Labels labels.Labels

	PID            int64
	ExecutablePath string
	ContainerID    string
	ServiceName    string

	// EnvAttributes are the attributes the process declared for itself; see
	// DeclaredAttributes.
	EnvAttributes []Attribute
}

// Declared is what a process declared about itself, as the profiler captured
// it.
type Declared struct {
	// Context are the resource attributes the profiler resolved for the
	// process: its OTEP 4719 process context if it publishes one, otherwise
	// the profiler's reading of the same OTel environment variables as Env.
	Context attribute.Set
	// Env are the process's OTel environment variables.
	Env map[libpf.String]libpf.String
}

// Attribute is one resource attribute.
type Attribute struct {
	Key, Value string
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

// PutProcessAttributes sets p's resource attributes: the standard process
// identity first, so a consumer that only speaks semconv still gets it, then
// the host attributes, then p's labels, so relabel rules keep the names
// operators configured. Labels with a semconv equivalent are
// renamed, unless a relabel rule already set that key itself: the explicit
// rule wins. The process's own OTEL_RESOURCE_ATTRIBUTES come last and only
// fill keys nothing else set, so a process can add service.namespace or
// deployment.environment.name but cannot claim another host or container.
func PutProcessAttributes(attrs pcommon.Map, p Process, nodeName string, inKubernetes bool) {
	if p.ServiceName != "" {
		attrs.PutStr(AttrServiceName, p.ServiceName)
	}
	if p.PID != 0 {
		attrs.PutInt(AttrProcessPID, p.PID)
	}
	if p.ExecutablePath != "" {
		attrs.PutStr(AttrProcessExePath, p.ExecutablePath)
	}
	if p.ContainerID != "" {
		attrs.PutStr(AttrContainerID, p.ContainerID)
	}
	PutHostAttributes(attrs, nodeName, inKubernetes)

	p.Labels.Range(func(l labels.Label) {
		name := l.Name
		if attr, ok := labelAttrs[name]; ok {
			if attr == "" || p.Labels.Has(attr) {
				return
			}
			name = attr
		}
		switch name {
		case "process.parent_pid":
			if pid, err := strconv.ParseInt(l.Value, 10, 64); err == nil {
				attrs.PutInt(name, pid)
			}
		case "container.image.tags", "container.image.repo_digests":
			values := attrs.PutEmptySlice(name)
			for _, value := range strings.Split(l.Value, ",") {
				values.AppendEmpty().SetStr(value)
			}
		default:
			attrs.PutStr(name, l.Value)
		}
	})

	for _, a := range p.EnvAttributes {
		if _, ok := attrs.Get(a.Key); !ok {
			attrs.PutStr(a.Key, a.Value)
		}
	}
}

// The OTel environment variables a process can use to name itself. Spelled out
// rather than taken from the SDK, which reads them for the agent's own resource
// rather than for a profiled process's.
// Interned once: the profiler interns the keys it captures, and libpf.String is
// a unique.Handle underneath, so an interned lookup is a pointer compare.
var (
	envServiceName        = libpf.Intern("OTEL_SERVICE_NAME")
	envResourceAttributes = libpf.Intern("OTEL_RESOURCE_ATTRIBUTES")
)

// ServiceName picks the service.name for a process. Consumers key resource
// identity on it, and apmName is set only for instrumented processes, so a
// system profiler needs the fallbacks or nearly every resource is anonymous.
//
// The process context comes first: an OTel SDK publishes the resource the
// application configured, usually in code rather than in the environment, and
// can update it during the process's life, so it is the authoritative source.
// For a process that publishes none, the profiler derives the context from the
// environment, which then gives the same name as the environment itself.
//
// The environment outranks comm because comm is the *thread* name: it comes
// from bpf_get_current_comm(), so a process that names its threads reports one
// resource per thread pool rather than one per service. A JVM fragments into
// "G1 Refine#0", "ForkJoinPool.co" and twenty others; OTEL_SERVICE_NAME
// collapses those back into the one service the operator actually named.
//
// comm still outranks the executable's basename because it is what top and ps
// show, and because a basename collapses every interpreted service into
// "python3". The kernel truncates comm to 15 characters, which is only
// cosmetic.
func ServiceName(apmName string, comm libpf.Comm, execPath libpf.String, d Declared) string {
	if apmName != "" {
		return apmName
	}
	if v, ok := d.Context.Value(AttrServiceName); ok {
		if s := strings.TrimSpace(v.Emit()); s != "" {
			return s
		}
	}
	if n := serviceNameFromEnv(d.Env); n != "" {
		return n
	}
	if c := comm.String(); c != "" {
		return c
	}
	if p := execPath.String(); p != "" {
		return path.Base(p)
	}
	return ""
}

// serviceNameFromEnv recovers a service name the process declared for itself.
// OTEL_SERVICE_NAME wins over a service.name in OTEL_RESOURCE_ATTRIBUTES, which
// is the precedence the OTel environment variable spec defines.
func serviceNameFromEnv(envVars map[libpf.String]libpf.String) string {
	if len(envVars) == 0 {
		return ""
	}
	if v, ok := envVars[envServiceName]; ok {
		if s := strings.TrimSpace(v.String()); s != "" {
			return s
		}
	}
	v, ok := envVars[envResourceAttributes]
	if !ok {
		return ""
	}
	for _, a := range parseResourceAttributes(v.String()) {
		if a.Key == AttrServiceName {
			return a.Value
		}
	}
	return ""
}

// DeclaredAttributes returns the attributes a process declared for itself
// other than service.name, which ServiceName resolves: those in its process
// context, then those in OTEL_RESOURCE_ATTRIBUTES for keys the context does
// not set. The result is deterministic: the context in key order, then the
// environment in the variable's order.
func DeclaredAttributes(d Declared) []Attribute {
	var attrs []Attribute
	for _, kv := range d.Context.ToSlice() {
		if kv.Key == AttrServiceName {
			continue
		}
		if v := kv.Value.Emit(); v != "" {
			attrs = append(attrs, Attribute{Key: string(kv.Key), Value: v})
		}
	}
	for _, a := range ResourceAttributesFromEnv(d.Env) {
		if !d.Context.HasValue(attribute.Key(a.Key)) {
			attrs = append(attrs, a)
		}
	}
	return attrs
}

// ResourceAttributesFromEnv returns the attributes in the process's
// OTEL_RESOURCE_ATTRIBUTES other than service.name, which ServiceName
// resolves. The result is in the variable's order, so equal environments give
// equal slices.
func ResourceAttributesFromEnv(envVars map[libpf.String]libpf.String) []Attribute {
	v, ok := envVars[envResourceAttributes]
	if !ok {
		return nil
	}
	attrs := parseResourceAttributes(v.String())
	n := 0
	for _, a := range attrs {
		if a.Key != AttrServiceName {
			attrs[n] = a
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return attrs[:n]
}

// parseResourceAttributes parses an OTEL_RESOURCE_ATTRIBUTES value: a W3C
// Baggage-shaped list of comma-separated key=value, with an optional
// ";"-delimited metadata part per entry that carries no resource meaning.
// Values are percent-encoded; an entry that fails to decode, or has an empty
// key or value, is skipped rather than reported as raw escapes.
func parseResourceAttributes(v string) []Attribute {
	var attrs []Attribute
	for pair := range strings.SplitSeq(v, ",") {
		k, val, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		val, _, _ = strings.Cut(val, ";")
		decoded, err := url.QueryUnescape(strings.TrimSpace(val))
		k, decoded = strings.TrimSpace(k), strings.TrimSpace(decoded)
		if err != nil || k == "" || decoded == "" {
			continue
		}
		attrs = append(attrs, Attribute{Key: k, Value: decoded})
	}
	return attrs
}
