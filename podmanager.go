// Copyright 2021 Polar Signals Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/pprof/profile"
	"github.com/polarsignals/polarsignals-agent/k8s"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodManager struct {
	logger log.Logger

	mtx *sync.RWMutex

	// node where this instance is running
	nodeName string

	// client to talk to the k8s API server to get information about pods
	k8sClient *k8s.K8sClient

	podInformer *k8s.PodInformer
	createdChan chan *v1.Pod
	deletedChan chan string
	// containerIDsByKey is a map maintained by the controller
	// key is "namespace/podname"
	// value is an set of containerId
	containerIDsByKey map[string]map[string]*ContainerProfiler
}

func (g *PodManager) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d := <-g.deletedChan:
			g.mtx.Lock()
			if containerIDs, ok := g.containerIDsByKey[d]; ok {
				for _, containerProfiler := range containerIDs {
					containerProfiler.Stop()
				}
			}
			delete(g.containerIDsByKey, d)
			g.mtx.Unlock()
		case c := <-g.createdChan:
			containers := g.k8sClient.PodToContainers(c)
			key, _ := cache.MetaNamespaceKeyFunc(c)

			g.mtx.RLock()
			containerIDs, ok := g.containerIDsByKey[key]
			g.mtx.RUnlock()
			if !ok {
				g.mtx.Lock()
				// Need to double check that it wasn't recently written.
				containerIDs, ok = g.containerIDsByKey[key]
				if !ok {
					containerIDs = make(map[string]*ContainerProfiler)
					g.containerIDsByKey[key] = containerIDs
				}
				g.mtx.Unlock()
			}
			for _, container := range containers {
				logger := log.With(g.logger, "namespace", container.Namespace, "pod", container.PodName, "container", container.ContainerName)
				level.Debug(logger).Log("msg", "adding container profiler")

				// The container is already registered, there is not any chance the
				// PID will change, so ignore it.
				g.mtx.RLock()
				_, ok := containerIDs[container.ContainerId]
				g.mtx.RUnlock()
				if ok {
					continue
				}

				g.mtx.Lock()
				_, ok = containerIDs[container.ContainerId]
				if ok {
					g.mtx.Unlock()
					continue
				}

				containerProfiler := NewContainerProfiler(logger, container)
				containerIDs[container.ContainerId] = containerProfiler
				g.mtx.Unlock()
				go func() {
					err := containerProfiler.Run(ctx)
					if err != nil {
						level.Error(logger).Log("msg", "running container profiler failed", "err", err)
					}
				}()
			}
		}
	}
}

func NewPodManager(logger log.Logger, nodeName string) (*PodManager, error) {
	createdChan := make(chan *v1.Pod)
	deletedChan := make(chan string)

	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}

	podInformer, err := k8s.NewPodInformer(nodeName, k8sClient.Clientset(), createdChan, deletedChan)
	if err != nil {
		return nil, err
	}
	g := &PodManager{
		logger:            logger,
		nodeName:          nodeName,
		podInformer:       podInformer,
		createdChan:       createdChan,
		deletedChan:       deletedChan,
		containerIDsByKey: make(map[string]map[string]*ContainerProfiler),
		k8sClient:         k8sClient,
		mtx:               &sync.RWMutex{},
	}

	return g, nil
}

func (m *PodManager) ActiveProfilers() []string {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	res := []string{}
	for nsPod, containerProfilers := range m.containerIDsByKey {
		for _, containerProfiler := range containerProfilers {
			res = append(res, nsPod+"/"+containerProfiler.ContainerName())
		}
	}

	return res
}

func (m *PodManager) LastProfileFrom(namespace, pod, container string) *profile.Profile {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	containers := m.containerIDsByKey[namespace+"/"+pod]
	for _, containerProfiler := range containers {
		if containerProfiler.ContainerName() == container {
			return containerProfiler.LastProfile()
		}
	}

	return nil
}
