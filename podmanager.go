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

	"github.com/conprof/conprof/pkg/store/storepb"
	"github.com/conprof/conprof/symbol"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/pprof/profile"
	"github.com/polarsignals/polarsignals-agent/k8s"
	"github.com/polarsignals/polarsignals-agent/ksym"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PodManager struct {
	logger log.Logger

	// node where this instance is running
	nodeName  string
	ksymCache *ksym.KsymCache

	// client to talk to the k8s API server to get information about pods
	k8sClient *k8s.K8sClient

	podInformer *k8s.PodInformer
	createdChan chan *v1.Pod
	deletedChan chan string
	// containerIDsByKey is a map maintained by the controller
	// key is "namespace/podname"
	// value is an set of containerId
	containerIDsByKey map[string]map[string]*ContainerProfiler
	mtx               *sync.RWMutex

	observers []*observer
	omtx      *sync.RWMutex

	writeClient  storepb.WritableProfileStoreClient
	symbolClient *symbol.SymbolStoreClient
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

			seenContainers := map[string]struct{}{}
			for _, container := range containers {
				seenContainers[container.ContainerId] = struct{}{}
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

				containerProfiler := NewContainerProfiler(
					logger,
					g.ksymCache,
					g.writeClient,
					g.symbolClient,
					container,
					g.ObserveProfile,
				)
				containerIDs[container.ContainerId] = containerProfiler
				g.mtx.Unlock()
				go func() {
					err := containerProfiler.Run(ctx)
					if err != nil {
						level.Error(logger).Log("msg", "running container profiler failed", "err", err)
					}
				}()
			}

			// Cleanup container restarts, where the pod doesn't go away, but
			// the individual container does. Thankfully we at least get
			// "created" events, so we can cleanup here.
			g.mtx.Lock()
			deleteIds := []string{}
			for containerId, profiler := range containerIDs {
				_, seen := seenContainers[containerId]
				if !seen {
					profiler.Stop()
					deleteIds = append(deleteIds, containerId)
				}
			}
			for _, containerId := range deleteIds {
				delete(containerIDs, containerId)
			}
			g.mtx.Unlock()
		}
	}
}

func NewPodManager(
	logger log.Logger,
	nodeName string,
	ksymCache *ksym.KsymCache,
	writeClient storepb.WritableProfileStoreClient,
	symbolClient *symbol.SymbolStoreClient,
) (*PodManager, error) {
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
		ksymCache:         ksymCache,
		podInformer:       podInformer,
		createdChan:       createdChan,
		deletedChan:       deletedChan,
		containerIDsByKey: make(map[string]map[string]*ContainerProfiler),
		k8sClient:         k8sClient,
		mtx:               &sync.RWMutex{},
		omtx:              &sync.RWMutex{},
		writeClient:       writeClient,
		symbolClient:      symbolClient,
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

type observer struct {
	f func(Record)
	m *PodManager
}

func (o *observer) Close() {
	o.m.RemoveObserver(o)
}

func (m *PodManager) ObserveProfile(r Record) {
	m.omtx.RLock()
	defer m.omtx.RUnlock()

	for _, o := range m.observers {
		o.f(r)
	}
}

func (m *PodManager) Observe(f func(Record)) *observer {
	m.omtx.Lock()
	defer m.omtx.Unlock()

	o := &observer{
		f: f,
		m: m,
	}
	m.observers = append(m.observers, o)
	return o
}

func (m *PodManager) RemoveObserver(o *observer) {
	m.omtx.Lock()
	defer m.omtx.Unlock()

	found := false
	i := 0
	for ; i < len(m.observers); i++ {
		if m.observers[i] == o {
			found = true
			break
		}
	}
	if found {
		m.observers = append(m.observers[:i], m.observers[i+1:]...)
	}
}

func (m *PodManager) LastProfileFrom(ctx context.Context, namespace, pod, container string) *profile.Profile {
	pCh := make(chan *profile.Profile)
	defer close(pCh)

	o := m.Observe(func(r Record) {
		l := map[string]string{}
		for _, label := range r.Labels {
			l[label.Name] = label.Value
		}
		if l["namespace"] == namespace && l["pod"] == pod && l["container"] == container {
			pCh <- r.Profile.Copy()
		}
	})
	defer o.Close()

	select {
	case p := <-pCh:
		return p
	case <-ctx.Done():
		return nil
	}
}
