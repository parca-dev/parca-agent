// Copyright 2022-2023 The Parca Authors
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

package discovery

import (
	"context"
	"fmt"

	"github.com/go-kit/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/util/strutil"
	v1 "k8s.io/api/core/v1"

	"github.com/parca-dev/parca-agent/pkg/discovery/kubernetes"
)

type PodConfig struct {
	nodeName   string
	socketPath string
}

type PodDiscoverer struct {
	logger log.Logger

	podInformer *kubernetes.PodInformer
	createdChan chan *v1.Pod
	deletedChan chan string
	k8sClient   *kubernetes.Client
}

func (c *PodConfig) Name() string {
	return c.nodeName
}

func NewPodConfig(nodeName, socketPath string) *PodConfig {
	return &PodConfig{
		nodeName:   nodeName,
		socketPath: socketPath,
	}
}

func (c *PodConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	createdChan := make(chan *v1.Pod)
	deletedChan := make(chan string)

	k8sClient, err := kubernetes.NewKubernetesClient(d.Logger, c.nodeName, c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	podInformer, err := kubernetes.NewPodInformer(d.Logger, c.nodeName, k8sClient.Clientset(), createdChan, deletedChan)
	if err != nil {
		return nil, err
	}
	g := &PodDiscoverer{
		logger:      d.Logger,
		podInformer: podInformer,
		createdChan: createdChan,
		deletedChan: deletedChan,
		k8sClient:   k8sClient,
	}
	return g, nil
}

func (g *PodDiscoverer) Run(ctx context.Context, up chan<- []Group) error {
	defer g.podInformer.Stop()
	defer g.k8sClient.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case key := <-g.deletedChan:
			// Prefix key with "pod/" to create identical key as podSourceFromNamespaceAndName()
			groups := []Group{&MultiTargetGroup{source: "pod/" + key}}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case up <- groups:
			}
		case pod := <-g.createdChan:
			containers := g.k8sClient.PodToContainers(pod)
			groups := []Group{g.buildGroup(pod, containers)}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case up <- groups:
			}
		}
	}
}

func (g *PodDiscoverer) buildGroup(pod *v1.Pod, containers []*kubernetes.ContainerDefinition) *MultiTargetGroup {
	tg := &MultiTargetGroup{
		source:  g.podSourceFromNamespaceAndName(pod.Namespace, pod.Name),
		labels:  model.LabelSet{},
		Targets: map[int]model.LabelSet{},
	}
	// PodIP can be empty when a pod is starting or has been evicted.
	if len(pod.Status.PodIP) == 0 {
		return tg
	}

	tg.labels["namespace"] = model.LabelValue(pod.ObjectMeta.Namespace)
	tg.labels["pod"] = model.LabelValue(pod.ObjectMeta.Name)

	// Expose shared labels
	for k, v := range pod.ObjectMeta.Labels {
		tg.labels[model.LabelName(strutil.SanitizeLabelName(k))] = model.LabelValue(v)
	}

	for _, container := range containers {
		tg.Targets[container.PID] = tg.Targets[container.PID].Merge(model.LabelSet{
			"container":   model.LabelValue(container.ContainerName),
			"containerid": model.LabelValue(container.ContainerID),
		})
	}

	return tg
}

func (g *PodDiscoverer) podSourceFromNamespaceAndName(namespace, name string) string {
	return "pod/" + namespace + "/" + name
}
