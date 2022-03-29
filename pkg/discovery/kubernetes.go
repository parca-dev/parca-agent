// Copyright 2021 The Parca Authors
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

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/k8s"
	"github.com/parca-dev/parca-agent/pkg/target"
)

type PodConfig struct {
	podLabelSelector string
	socketPath       string
	nodeName         string
}

type PodDiscoverer struct {
	logger log.Logger

	podInformer *k8s.PodInformer
	createdChan chan *v1.Pod
	deletedChan chan string
	k8sClient   *k8s.Client
}

func (c *PodConfig) Name() string {
	return c.nodeName
}

func NewPodConfig(podLabel, socketPath, nodeName string) *PodConfig {
	return &PodConfig{
		podLabelSelector: podLabel,
		socketPath:       socketPath,
		nodeName:         nodeName,
	}
}

func (c *PodConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	createdChan := make(chan *v1.Pod)
	deletedChan := make(chan string)

	k8sClient, err := k8s.NewK8sClient(d.Logger, c.nodeName, c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}

	podInformer, err := k8s.NewPodInformer(d.Logger, c.nodeName, c.podLabelSelector, k8sClient.Clientset(), createdChan, deletedChan)
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

func (g *PodDiscoverer) Run(ctx context.Context, up chan<- []*target.Group) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case key := <-g.deletedChan:
			// Prefix key with "pod/" to create identical key as podSourceFromNamespaceAndName()
			group := []*target.Group{{Source: "pod/" + key}}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case up <- group:
			}
		case pod := <-g.createdChan:
			containers := g.k8sClient.PodToContainers(pod)
			groups := []*target.Group{buildPod(pod, containers)}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case up <- groups:
			}
		}
	}
}

func buildPod(pod *v1.Pod, containers []*k8s.ContainerDefinition) *target.Group {
	tg := &target.Group{
		Source: podSourceFromNamespaceAndName(pod.Namespace, pod.Name),
		Labels: model.LabelSet{},
	}
	// PodIP can be empty when a pod is starting or has been evicted.
	if len(pod.Status.PodIP) == 0 {
		return tg
	}

	tg.Labels["namespace"] = model.LabelValue(pod.ObjectMeta.Namespace)
	tg.Labels["pod"] = model.LabelValue(pod.ObjectMeta.Name)

	// Expose shared labels
	for k, v := range pod.ObjectMeta.Labels {
		tg.Labels[model.LabelName(strutil.SanitizeLabelName(k))] = model.LabelValue(v)
	}

	for _, container := range containers {
		tg.Targets = append(tg.Targets, model.LabelSet{
			"container":               model.LabelValue(container.ContainerName),
			"containerid":             model.LabelValue(container.ContainerID),
			agent.CgroupPathLabelName: model.LabelValue(container.PerfEventCgroupPath()),
		})
	}

	return tg
}

func podSourceFromNamespaceAndName(namespace, name string) string {
	return "pod/" + namespace + "/" + name
}
