// Copyright 2022-2024 The Parca Authors
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
	"context"
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestContainerMetadataLabelModes(t *testing.T) {
	for _, tc := range []struct {
		name, image, imageName, tag, digest string
		cfg                                 Config
	}{
		{name: "arrow", image: "registry:5000/app:v3@sha256:abcdef"},
		{name: "OTLP tagged digest", cfg: Config{Semconv: true}, image: "registry:5000/app:v3@sha256:abcdef", imageName: "registry:5000/app", tag: "v3", digest: "registry:5000/app@sha256:abcdef"},
		{name: "OTLP tag", cfg: Config{Semconv: true}, image: "registry:5000/app:v2", imageName: "registry:5000/app", tag: "v2"},
		{name: "OTLP registry port only", cfg: Config{Semconv: true}, image: "registry:5000/app", imageName: "registry:5000/app"},
		{name: "OTLP digest", cfg: Config{Semconv: true}, image: "team/app@sha256:abcdef", imageName: "team/app", digest: "team/app@sha256:abcdef"},
		{name: "OTLP with relabel rules", cfg: Config{Semconv: true, KeepDiscoveryLabels: true}, image: "team/app:v4", imageName: "team/app", tag: "v4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids, err := lru.NewSynced[libpf.PID, containerIDEntry](16, libpf.PID.Hash32)
			require.NoError(t, err)
			cache, err := lru.NewSynced[string, model.LabelSet](16, hashString)
			require.NoError(t, err)
			p := &containerMetadataProvider{
				cfg: tc.cfg, containerIDCache: ids, containerMetadataCache: cache,
				kubernetesNode: &corev1.Node{ObjectMeta: v1.ObjectMeta{Labels: map[string]string{
					"topology.kubernetes.io/region": "eu-central-1",
					"topology.kubernetes.io/zone":   "eu-central-1b",
				}}},
			}
			controller := true
			pod := &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name: "checkout-abc-xyz", Namespace: "production", UID: "pod-uid",
					Labels:          map[string]string{"customer": "unrequested"},
					OwnerReferences: []v1.OwnerReference{{Kind: "ReplicaSet", Name: "checkout-abc", Controller: &controller}},
				},
				Spec: corev1.PodSpec{
					NodeName:   "node-7",
					Containers: []corev1.Container{{Name: "server", Image: tc.image}},
				},
				Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "server", ContainerID: "containerd://deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}},
			}
			// Feed the same pod update as the informer and a cgroup lookup result.
			p.addPodContainerLabels(pod)
			ids.Add(123, containerIDEntry{containerID: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", env: envKubernetes})
			lb := labels.NewBuilder(labels.EmptyLabels())
			require.True(t, p.AddMetadata(context.Background(), 123, lb))
			got := lb.Labels()
			if !tc.cfg.Semconv {
				require.Empty(t, got.Get("k8s.pod.name"))
				require.Equal(t, tc.image, got.Get("__meta_kubernetes_pod_container_image"))
				return
			}
			for k, v := range map[string]string{
				"k8s.namespace.name": "production", "k8s.pod.name": "checkout-abc-xyz", "k8s.pod.uid": "pod-uid",
				"k8s.node.name": "node-7", "k8s.container.name": "server", "k8s.replicaset.name": "checkout-abc",
				"container.id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
				"cloud.region": "eu-central-1", "cloud.availability_zone": "eu-central-1b",
				"container.image.name": tc.imageName, "container.image.tags": tc.tag, "container.image.repo_digests": tc.digest,
			} {
				require.Equal(t, v, got.Get(k), k)
			}
			require.Empty(t, got.Get("k8s.deployment.name"), "a ReplicaSet is not necessarily a Deployment")
			if tc.cfg.KeepDiscoveryLabels {
				require.Equal(t, "unrequested", got.Get("__meta_kubernetes_pod_label_customer"))
			} else {
				got.Range(func(l labels.Label) { require.NotContains(t, l.Name, "__meta_") })
				require.Empty(t, got.Get("customer"))
			}
		})
	}
}

func TestMatchContainerID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "containerd prefixed ID",
			input: "containerd://a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e",
			want:  "a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e",
		},
		{
			name:  "docker prefixed ID",
			input: "docker://55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
			want:  "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
		},
		{
			name:  "cri-o prefixed ID",
			input: "cri-o://deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			want:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		{
			name:  "bare container ID from CRI API",
			input: "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
			want:  "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03a",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "short hex string",
			input:   "a4fdf2f3",
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			input:   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantErr: true,
		},
		{
			name:    "65 hex chars rejected",
			input:   "a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e0",
			wantErr: true,
		},
		{
			name:    "cgroup path not matched",
			input:   "12:memory:/kubepods/burstable/pod123/a4fdf2f34a84387639c1e763e50f114dd9374585d4dc287a6ae72ee8b762790e",
			wantErr: true,
		},
		{
			name:    "hex with trailing chars rejected",
			input:   "55223482fd5cb7e89c6fda81b893aa4d714f4a3d0b560fa8c9d3820717cdb03axyz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := matchContainerID(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
