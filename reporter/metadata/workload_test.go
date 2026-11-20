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
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodWorkload(t *testing.T) {
	yes := true
	owned := func(kind, name string) []v1.OwnerReference {
		return []v1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
	}
	ctr := &corev1.Container{Name: "main"}
	for _, tc := range []struct {
		name string
		meta v1.ObjectMeta
		want string
	}{
		{"annotation first", v1.ObjectMeta{
			Annotations: map[string]string{serviceNameAnnotation: "annotated"},
			Labels:      map[string]string{"app.kubernetes.io/instance": "inst", "app.kubernetes.io/name": "app"},
		}, "annotated"},
		{"instance before name", v1.ObjectMeta{
			Labels: map[string]string{"app.kubernetes.io/instance": "inst", "app.kubernetes.io/name": "app"},
		}, "inst"},
		{"name label", v1.ObjectMeta{
			Labels:          map[string]string{"app.kubernetes.io/name": "app"},
			OwnerReferences: owned("StatefulSet", "db"),
		}, "app"},
		{"deployment from replicaset", v1.ObjectMeta{
			Name:            "vllm-7d9f8c6b5-x2x9z",
			Labels:          map[string]string{"pod-template-hash": "7d9f8c6b5"},
			OwnerReferences: owned("ReplicaSet", "vllm-7d9f8c6b5"),
		}, "vllm"},
		{"bare replicaset", v1.ObjectMeta{OwnerReferences: owned("ReplicaSet", "rs")}, "rs"},
		{"statefulset", v1.ObjectMeta{Name: "db-0", OwnerReferences: owned("StatefulSet", "db")}, "db"},
		{"daemonset", v1.ObjectMeta{OwnerReferences: owned("DaemonSet", "dcgm")}, "dcgm"},
		{"cronjob from job", v1.ObjectMeta{OwnerReferences: owned("Job", "nightly-29145600")}, "nightly"},
		{"job", v1.ObjectMeta{OwnerReferences: owned("Job", "train-run")}, "train-run"},
		{"unknown owner: pod name", v1.ObjectMeta{Name: "p", OwnerReferences: owned("RayCluster", "r")}, "p"},
		{"pod name", v1.ObjectMeta{Name: "p"}, "p"},
		{"container name", v1.ObjectMeta{}, "main"},
	} {
		tc.meta.Namespace = "ml"
		got := podWorkload(&corev1.Pod{ObjectMeta: tc.meta}, ctr)
		if got.Name != tc.want || got.Namespace != "ml" {
			t.Errorf("%s: %+v, want %q in ml", tc.name, got, tc.want)
		}
	}
}
