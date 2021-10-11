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

package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/k8s"
	"github.com/parca-dev/parca-agent/pkg/ksym"
)

type PodManager struct {
	logger log.Logger

	externalLabels map[string]string

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
	containerIDsByKey map[string]map[string]*CgroupProfiler
	mtx               *sync.RWMutex

	writeClient     profilestorepb.ProfileStoreServiceClient
	debugInfoClient debuginfo.Client
	sink            func(Record)

	samplingRatio     float64
	tmpDir            string
	profilingDuration time.Duration
}

func (g *PodManager) SetSink(sink func(Record)) {
	g.sink = sink
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
					containerIDs = make(map[string]*CgroupProfiler)
					g.containerIDsByKey[key] = containerIDs
				}
				g.mtx.Unlock()
			}

			seenContainers := map[string]struct{}{}
			for _, container := range containers {
				logger := log.With(g.logger, "namespace", container.Namespace, "pod", container.PodName, "container", container.ContainerName)
				containerProfiler := NewCgroupProfiler(
					logger,
					g.externalLabels,
					g.ksymCache,
					g.writeClient,
					g.debugInfoClient,
					container,
					g.profilingDuration,
					g.sink,
					g.tmpDir,
				)
				if !probabilisticSampling(g.samplingRatio, containerProfiler.Labels()) {
					// This target is not being sampled.
					continue
				}
				level.Debug(logger).Log("msg", "adding container profiler")

				seenContainers[container.ContainerId] = struct{}{}

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
	externalLabels map[string]string,
	nodeName string,
	podLabelSelector string,
	samplingRatio float64,
	ksymCache *ksym.KsymCache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	tmp string,
	socketPath string,
	profilingDuration time.Duration,
) (*PodManager, error) {
	createdChan := make(chan *v1.Pod)
	deletedChan := make(chan string)

	k8sClient, err := k8s.NewK8sClient(logger, nodeName, socketPath)
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}

	podInformer, err := k8s.NewPodInformer(logger, nodeName, podLabelSelector, k8sClient.Clientset(), createdChan, deletedChan)
	if err != nil {
		return nil, err
	}
	g := &PodManager{
		logger:            logger,
		externalLabels:    externalLabels,
		nodeName:          nodeName,
		samplingRatio:     samplingRatio,
		ksymCache:         ksymCache,
		podInformer:       podInformer,
		createdChan:       createdChan,
		deletedChan:       deletedChan,
		containerIDsByKey: make(map[string]map[string]*CgroupProfiler),
		k8sClient:         k8sClient,
		mtx:               &sync.RWMutex{},
		writeClient:       writeClient,
		debugInfoClient:   debugInfoClient,
		tmpDir:            tmp,
		profilingDuration: profilingDuration,
	}

	return g, nil
}

func (m *PodManager) ActiveProfilers() []Profiler {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	res := []Profiler{}
	for _, containerProfilers := range m.containerIDsByKey {
		for _, containerProfiler := range containerProfilers {
			res = append(res, containerProfiler)
		}
	}

	return res
}
