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
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"
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
// the host attributes, then p's labels, so relabel rules and external labels
// keep the names operators configured. Labels with a semconv equivalent are
// renamed, unless a relabel rule already set that key itself: the explicit
// rule wins.
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
		attrs.PutStr(name, l.Value)
	})
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
// The environment outranks comm because comm is the *thread* name: it comes
// from bpf_get_current_comm(), so a process that names its threads reports one
// resource per thread pool rather than one per service. A JVM fragments into
// "G1 Refine#0", "ForkJoinPool.co" and twenty others; OTEL_SERVICE_NAME
// collapses those back into the one service the operator actually named.
//
// Caveat: this reads /proc/<pid>/environ, which is fixed at exec. Once the
// agent supports process context -- where a process publishes its own resource
// attributes for the profiler to read at sample time -- that source is both
// authoritative and able to change during the process's life, so it must take
// precedence over anything recovered from the environment here.
//
// comm still outranks the executable's basename because it is what top and ps
// show, and because a basename collapses every interpreted service into
// "python3". The kernel truncates comm to 15 characters, which is only
// cosmetic.
func ServiceName(apmName string, comm libpf.Comm, execPath libpf.String,
	envVars map[libpf.String]libpf.String,
) string {
	if apmName != "" {
		return apmName
	}
	if n := serviceNameFromEnv(envVars); n != "" {
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
	// A W3C Baggage-shaped list: comma-separated key=value, with an optional
	// ";"-delimited metadata part per entry that carries no resource meaning.
	for pair := range strings.SplitSeq(v.String(), ",") {
		k, val, found := strings.Cut(pair, "=")
		if !found || strings.TrimSpace(k) != AttrServiceName {
			continue
		}
		val, _, _ = strings.Cut(val, ";")
		// Values are percent-encoded; a name needing it is unusual enough that
		// a decode failure is better reported as "no name" than as raw escapes.
		decoded, err := url.QueryUnescape(strings.TrimSpace(val))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(decoded)
	}
	return ""
}
