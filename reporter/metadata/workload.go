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

package metadata

import (
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	corev1 "k8s.io/api/core/v1"
)

// Workload names a process from its Kubernetes pod.
type Workload struct {
	// Name is the service.name OpenTelemetry infers for the pod's container
	// (podWorkload).
	Name string
	// Namespace is the pod's namespace.
	Namespace string
}

// WorkloadProvider is a MetadataProvider that names a process's workload from
// what pod discovery has cached. It never calls out, so it is cheap enough to
// ask on a hot path.
type WorkloadProvider interface {
	Workload(pid libpf.PID) (Workload, bool)
}

// Workload returns the workload of pid's pod, if discovery has seen the pod.
func (p *containerMetadataProvider) Workload(pid libpf.PID) (Workload, bool) {
	if p.workloadCache == nil {
		return Workload{}, false
	}
	id, env, err := p.lookupContainerID(pid)
	if err != nil || !isContainerEnvironment(env, envKubernetes) {
		return Workload{}, false
	}
	return p.workloadCache.Get(id)
}

// OpenTelemetry's annotation that sets a pod's service.name.
const serviceNameAnnotation = "resource.opentelemetry.io/service.name"

// podWorkload names container c of pod as OpenTelemetry infers service.name
// on Kubernetes (the operator and the collector's k8sattributes processor):
// the first of the resource.opentelemetry.io/service.name annotation, the
// app.kubernetes.io/instance and app.kubernetes.io/name labels, then the
// name of the pod's Deployment, ReplicaSet, StatefulSet, DaemonSet, CronJob
// or Job, the pod's name, and the container's name.
func podWorkload(pod *corev1.Pod, c *corev1.Container) Workload {
	w := Workload{Namespace: pod.Namespace}
	for _, v := range []string{
		pod.Annotations[serviceNameAnnotation],
		pod.Labels["app.kubernetes.io/instance"],
		pod.Labels["app.kubernetes.io/name"],
		ownerName(pod),
		pod.Name,
		c.Name,
	} {
		if v != "" {
			w.Name = v
			break
		}
	}
	return w
}

// ownerName returns the name of the workload controlling pod. Only the
// immediate owner is known, so a Deployment is recognized by the
// pod-template-hash suffix of its ReplicaSet, and a CronJob by the numeric
// suffix of its Job, as the collector's k8sattributes processor does.
func ownerName(pod *corev1.Pod) string {
	ref := GetControllerOf(pod)
	if ref == nil {
		return ""
	}
	switch ref.Kind {
	case "ReplicaSet":
		if h := pod.Labels["pod-template-hash"]; h != "" {
			if d, ok := strings.CutSuffix(ref.Name, "-"+h); ok && d != "" {
				return d
			}
		}
		return ref.Name
	case "Job":
		if i := strings.LastIndexByte(ref.Name, '-'); i > 0 && allDigits(ref.Name[i+1:]) {
			return ref.Name[:i]
		}
		return ref.Name
	case "StatefulSet", "DaemonSet", "Deployment", "CronJob", "ReplicationController":
		return ref.Name
	}
	return ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
