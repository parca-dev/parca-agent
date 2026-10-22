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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/parca-dev/parca-agent/reporter/processlabels"
)

// ProcessResourcer renders the OTLP resource attributes of a process using a
// GPU.
type ProcessResourcer interface {
	// PutResource sets pid's resource attributes on attrs. It returns false
	// if the process must not be reported, because a relabel rule dropped it.
	PutResource(pid uint32, attrs pcommon.Map) bool
}

// DeclaredLookup returns what pid declared about itself as the profiler
// captured it: its process context and the OTel environment variables read
// when the profiler synchronized the process. ok is false if the profiler does
// not track pid.
type DeclaredLookup func(pid libpf.PID) (d processlabels.Declared, ok bool)

// processResourcer builds a process's resource the way parca-agent builds the
// resource of its profiles: the shared label resolver (metadata providers and
// relabel config) and the shared semconv rendering. NVML reports host PIDs, so
// procRoot must be the host's procfs, as it is when running in the host PID
// namespace like parca-agent.
type processResourcer struct {
	ctx          context.Context
	resolver     *processlabels.Resolver
	declared     DeclaredLookup
	nodeName     string
	inKubernetes bool
	procRoot     string
}

// NewProcessResourcer returns a ProcessResourcer backed by resolver. declared
// may be nil, in which case the environment is read from procfs.
func NewProcessResourcer(ctx context.Context, resolver *processlabels.Resolver, declared DeclaredLookup,
	nodeName string, inKubernetes bool,
) ProcessResourcer {
	return &processResourcer{
		ctx:          ctx,
		resolver:     resolver,
		declared:     declared,
		nodeName:     nodeName,
		inKubernetes: inKubernetes,
		procRoot:     "/proc",
	}
}

func (r *processResourcer) PutResource(pid uint32, attrs pcommon.Map) bool {
	res := r.resolver.Resolve(r.ctx, libpf.PID(pid), nil)
	if !res.Keep {
		return false
	}
	// Best effort: the process may have exited since NVML sampled it.
	procDir := filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10))
	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))
	declared, ok := r.lookupDeclared(libpf.PID(pid))
	if !ok {
		declared = processlabels.Declared{Env: otelEnv(procDir)}
	}
	processlabels.PutProcessAttributes(attrs, processlabels.Process{
		Labels:         res.Labels,
		PID:            int64(pid),
		ExecutablePath: exe,
		ServiceName: processlabels.ServiceName("",
			libpf.NewCommFromString(res.Labels.Get("comm")), libpf.Intern(exe), declared),
		EnvAttributes: processlabels.DeclaredAttributes(declared),
	}, r.nodeName, r.inKubernetes)
	return true
}

// lookupDeclared returns what the profiler captured for pid. Prefer it over
// procfs: it carries the process context, which procfs can't, and
// setproctitle overwrites the memory /proc/<pid>/environ reads from, so once a
// process renames itself (vLLM's "VLLM::EngineCore", for one) its OTel
// variables are gone from there, but not from the profiler's copy, which is
// also what its profiles are named from.
func (r *processResourcer) lookupDeclared(pid libpf.PID) (processlabels.Declared, bool) {
	if r.declared == nil {
		return processlabels.Declared{}, false
	}
	return r.declared(pid)
}

// otelEnv returns the OTel variables a process can name itself with, from its
// environment, the same ones profiles honor, so a process's GPU metrics and
// NVTX spans land on the same resource as its profiles. It is the fallback for
// a process the profiler has not synchronized yet. Read on every call: it is a
// small file, and callers resolve each process about once a second.
func otelEnv(procDir string) map[libpf.String]libpf.String {
	data, err := os.ReadFile(filepath.Join(procDir, "environ"))
	if err != nil {
		return nil
	}
	var env map[libpf.String]libpf.String
	for kv := range bytes.SplitSeq(data, []byte{0}) {
		k, v, ok := bytes.Cut(kv, []byte{'='})
		if !ok {
			continue
		}
		switch string(k) {
		case "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES":
			if env == nil {
				env = make(map[libpf.String]libpf.String, 2)
			}
			env[libpf.Intern(string(k))] = libpf.Intern(string(v))
		}
	}
	return env
}
