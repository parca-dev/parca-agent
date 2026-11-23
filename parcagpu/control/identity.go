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

package control

import (
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// Identity is what workload settings match a process by.
type Identity struct {
	// Name is the service.name the process declares or, failing that, the
	// one OTel infers from its Kubernetes pod.
	Name string
	// ServiceNamespace is the service.namespace the process declares.
	ServiceNamespace string
	// K8sNamespace is its pod's namespace.
	K8sNamespace string
}

// Namers look up what names a process. Either may be nil.
type Namers struct {
	// Resource returns the resource the profiler resolved for pid: the
	// service.name and service.namespace it declares in OTEL_SERVICE_NAME,
	// OTEL_RESOURCE_ATTRIBUTES or its process context. ok is false if the
	// profiler hasn't seen pid yet.
	Resource func(pid int) (res attribute.Set, ok bool)
	// Workload returns the service.name OTel infers for pid's Kubernetes
	// pod, and the pod's namespace, from what pod discovery has cached.
	Workload func(pid int) (name, namespace string, ok bool)
}

// podRetry paces Kubernetes lookups for a process its resource doesn't name:
// discovery may not have seen its pod yet.
const podRetry = time.Second

// procInfo is what the controller knows of a process outside procctl.
type procInfo struct {
	lastActive time.Time // last kernel activity
	id         Identity

	resSeen   bool               // resKey is set
	resKey    attribute.Distinct // the resource id was resolved from
	named     bool               // the resource gave id.Name
	podLookup time.Time          // last Kubernetes lookup
}

// procs tracks processes' activity and identity. Safe for concurrent use:
// the profiler reports activity from its own goroutines.
type procs struct {
	mu     sync.Mutex
	namers Namers
	m      map[int]*procInfo
}

func newProcs() *procs { return &procs{m: map[int]*procInfo{}} }

func (ps *procs) setNamers(n Namers) {
	ps.mu.Lock()
	ps.namers = n
	ps.mu.Unlock()
}

// get returns pid's entry, creating it. ps.mu must be held.
func (ps *procs) get(pid int) *procInfo {
	p := ps.m[pid]
	if p == nil {
		p = &procInfo{}
		ps.m[pid] = p
	}
	return p
}

// attached names a process procctl just found, from what the profiler has
// resolved for it so far.
func (ps *procs) attached(pid int) {
	ps.mu.Lock()
	n := ps.namers
	ps.mu.Unlock()
	var res attribute.Set
	var ok bool
	if n.Resource != nil {
		res, ok = n.Resource(pid)
	}
	id, named := identify(n, pid, res)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p := ps.get(pid)
	if p.resSeen {
		return // a sample beat us to it, with a resource at least as new
	}
	p.id, p.named, p.podLookup = id, named, time.Now()
	if ok {
		p.resSeen, p.resKey = true, res.Equivalent()
	}
}

// active records kernel activity, and checks pid's identity against res,
// the resource of the sample that showed it (empty if the sample has none).
// A process that wasn't named when procctl found it, or that names itself
// later (an SDK publishing its process context, say), gets its workload's
// settings at the next tick. It is on the profiler's hot path: most calls
// compare one key, and none calls back into the profiler.
func (ps *procs) active(pid int, res attribute.Set) {
	now := time.Now()
	ps.mu.Lock()
	p := ps.get(pid)
	p.lastActive = now
	n := ps.namers
	newRes := res.Len() > 0 && (!p.resSeen || res.Equivalent() != p.resKey)
	// Not named by its resource, and discovery hadn't seen its pod: it may
	// have by now.
	retryPod := !newRes && !p.named && p.id.K8sNamespace == "" && n.Workload != nil &&
		now.Sub(p.podLookup) >= podRetry
	if newRes {
		p.resSeen, p.resKey = true, res.Equivalent()
	}
	if newRes || retryPod {
		p.podLookup = now
	}
	ps.mu.Unlock()

	switch {
	case newRes:
		id, named := identify(n, pid, res)
		ps.mu.Lock()
		if p := ps.m[pid]; p != nil {
			p.id, p.named = id, named
		}
		ps.mu.Unlock()
	case retryPod:
		name, ns, ok := n.Workload(pid)
		if !ok {
			return
		}
		ps.mu.Lock()
		if p := ps.m[pid]; p != nil && !p.named {
			p.id.Name, p.id.K8sNamespace = name, ns
		}
		ps.mu.Unlock()
	}
}

// lookup returns pid's last kernel activity and identity.
func (ps *procs) lookup(pid int) (time.Time, Identity) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if p := ps.m[pid]; p != nil {
		return p.lastActive, p.id
	}
	return time.Time{}, Identity{}
}

// forget drops pid.
func (ps *procs) forget(pid int) {
	ps.mu.Lock()
	delete(ps.m, pid)
	ps.mu.Unlock()
}

// prune drops processes procctl doesn't control that ran no kernels within
// idle: the profiler reports activity for every CUDA process, instrumented
// or not, and only controlled ones are forgotten when they exit.
func (ps *procs) prune(controlled func(pid int) bool, now time.Time, idle time.Duration) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for pid, p := range ps.m {
		if now.Sub(p.lastActive) > idle && !controlled(pid) {
			delete(ps.m, pid)
		}
	}
}

// identify names pid: by the service.name its resource declares, else by its
// Kubernetes pod. named reports the former.
func identify(n Namers, pid int, res attribute.Set) (id Identity, named bool) {
	if v, ok := res.Value("service.name"); ok {
		// The SDKs' fallback when nothing names the service names nothing.
		if name := v.AsString(); !strings.HasPrefix(name, "unknown_service") {
			id.Name, named = name, true
		}
	}
	if v, ok := res.Value("service.namespace"); ok {
		id.ServiceNamespace = v.AsString()
	}
	if n.Workload != nil {
		if name, ns, ok := n.Workload(pid); ok {
			id.K8sNamespace = ns
			if id.Name == "" {
				id.Name = name
			}
		}
	}
	return id, named
}
