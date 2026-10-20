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

// processResourcer builds a process's resource the way parca-agent builds the
// resource of its profiles: the shared label resolver (metadata providers and
// relabel config) and the shared semconv rendering. NVML reports host PIDs, so
// procRoot must be the host's procfs, as it is when running in the host PID
// namespace like parca-agent.
type processResourcer struct {
	ctx          context.Context
	resolver     *processlabels.Resolver
	nodeName     string
	inKubernetes bool
	procRoot     string
}

// NewProcessResourcer returns a ProcessResourcer backed by resolver.
func NewProcessResourcer(ctx context.Context, resolver *processlabels.Resolver, nodeName string, inKubernetes bool) ProcessResourcer {
	return &processResourcer{
		ctx:          ctx,
		resolver:     resolver,
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
	exe, _ := os.Readlink(filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10), "exe"))
	processlabels.PutProcessAttributes(attrs, processlabels.Process{
		Labels:         res.Labels,
		PID:            int64(pid),
		ExecutablePath: exe,
		ServiceName: processlabels.ServiceName("",
			libpf.NewCommFromString(res.Labels.Get("comm")), libpf.Intern(exe), nil),
	}, r.nodeName, r.inKubernetes)
	return true
}
