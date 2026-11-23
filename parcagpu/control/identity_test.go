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
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

func resource(kv ...string) attribute.Set {
	var attrs []attribute.KeyValue
	for i := 0; i+1 < len(kv); i += 2 {
		attrs = append(attrs, attribute.String(kv[i], kv[i+1]))
	}
	return attribute.NewSet(attrs...)
}

func TestIdentify(t *testing.T) {
	pod := Namers{Workload: func(int) (string, string, bool) { return "deploy", "ml", true }}
	for _, tc := range []struct {
		name  string
		n     Namers
		res   attribute.Set
		want  Identity
		named bool
	}{
		{"nothing", Namers{}, attribute.Set{}, Identity{}, false},
		{"resource", Namers{}, resource("service.name", "vllm", "service.namespace", "prod"),
			Identity{Name: "vllm", ServiceNamespace: "prod"}, true},
		{"resource beats pod", pod, resource("service.name", "vllm"),
			Identity{Name: "vllm", K8sNamespace: "ml"}, true},
		{"pod", pod, attribute.Set{}, Identity{Name: "deploy", K8sNamespace: "ml"}, false},
		{"unknown_service is no name", pod, resource("service.name", "unknown_service:python"),
			Identity{Name: "deploy", K8sNamespace: "ml"}, false},
	} {
		id, named := identify(tc.n, 1, tc.res)
		if id != tc.want || named != tc.named {
			t.Errorf("%s: %+v %v, want %+v %v", tc.name, id, named, tc.want, tc.named)
		}
	}
}

// A process unnamed when procctl finds it is named by a later sample; a
// changed resource renames it; one its resource doesn't name is named by
// its pod once discovery sees it, looked up no more than once per podRetry.
func TestProcsNaming(t *testing.T) {
	ps := newProcs()
	var resolved bool
	var podSeen bool
	var podLookups int
	ps.setNamers(Namers{
		Resource: func(int) (attribute.Set, bool) {
			if !resolved {
				return attribute.Set{}, false
			}
			return resource("service.name", "early"), true
		},
		Workload: func(int) (string, string, bool) {
			podLookups++
			return "deploy", "ml", podSeen
		},
	})
	name := func(pid int) string { _, id := ps.lookup(pid); return id.Name }

	ps.attached(1) // before the profiler resolved it
	if name(1) != "" {
		t.Fatalf("named %q before anything named it", name(1))
	}
	ps.active(1, attribute.Set{}) // a kernel timing event: no resource
	if name(1) != "" {
		t.Fatalf("named %q", name(1))
	}
	ps.active(1, resource("service.name", "vllm"))
	if name(1) != "vllm" {
		t.Fatalf("sample didn't name it: %q", name(1))
	}
	ps.active(1, resource("service.name", "vllm2"))
	if name(1) != "vllm2" {
		t.Fatalf("changed resource didn't rename it: %q", name(1))
	}

	// Attach after a sample named it keeps the sample's name.
	ps.active(2, resource("service.name", "late"))
	resolved = true
	ps.attached(2)
	if name(2) != "late" {
		t.Fatalf("attach overrode the sample: %q", name(2))
	}

	// Named by its pod once discovery has it, retried at most once per
	// podRetry while it hasn't.
	resolved = false
	ps.attached(3)
	before := podLookups
	for i := 0; i < 100; i++ {
		ps.active(3, attribute.Set{})
	}
	if podLookups != before {
		t.Fatalf("%d pod lookups within podRetry of attach", podLookups-before)
	}
	podSeen = true
	ps.mu.Lock()
	ps.m[3].podLookup = time.Now().Add(-podRetry)
	ps.mu.Unlock()
	ps.active(3, attribute.Set{})
	if name(3) != "deploy" {
		t.Fatalf("pod didn't name it: %q", name(3))
	}
	before = podLookups
	ps.mu.Lock()
	ps.m[3].podLookup = time.Time{}
	ps.mu.Unlock()
	ps.active(3, attribute.Set{})
	if podLookups != before {
		t.Fatal("looked the pod up again after it was found")
	}

	// Prune drops what procctl doesn't control once idle.
	ps.prune(func(pid int) bool { return pid == 1 }, time.Now().Add(time.Hour), time.Minute)
	if _, ok := ps.m[1]; !ok || len(ps.m) != 1 {
		t.Fatalf("after prune: %v", ps.m)
	}
	ps.forget(1)
	if len(ps.m) != 0 {
		t.Fatalf("after forget: %v", ps.m)
	}
}
