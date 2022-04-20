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

package k8s

import (
	"fmt"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	// Registers default auth client.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type PodInformer struct {
	logger log.Logger

	indexer  cache.Indexer
	queue    workqueue.RateLimitingInterface
	informer cache.Controller

	stop           chan struct{}
	createdPodChan chan *v1.Pod
	deletedPodChan chan string
}

func NewPodInformer(logger log.Logger, node, podLabelSelector string, clientset kubernetes.Interface, createdPodChan chan *v1.Pod, deletedPodChan chan string) (*PodInformer, error) {
	optionsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
		options.LabelSelector = podLabelSelector
	}
	podListWatcher := cache.NewFilteredListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", "", optionsModifier)

	// creates the queue
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	indexer, informer := cache.NewIndexerInformer(podListWatcher, &v1.Pod{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
		//nolint:predeclared
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// IndexerInformer uses a delta queue, therefore for deletes we have to use this
			// key function.
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	}, cache.Indexers{})

	p := &PodInformer{
		logger:         logger,
		indexer:        indexer,
		queue:          queue,
		informer:       informer,
		stop:           make(chan struct{}),
		createdPodChan: createdPodChan,
		deletedPodChan: deletedPodChan,
	}

	// Now let's start the controller
	go p.Run(1, p.stop)

	return p, nil
}

func (p *PodInformer) Stop() {
	close(p.stop)
}

func (p *PodInformer) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := p.queue.Get()
	if quit {
		return false
	}

	defer p.queue.Done(key)

	item, ok := key.(string)
	if !ok {
		level.Error(p.logger).Log("msg", "failed to process item", "msg", "item is not a string")
		return true
	}

	if err := p.notifyChans(item); err != nil {
		level.Error(p.logger).Log("msg", "failed to process item", "item", item, "err", err)
	}
	return true
}

// notifyChans passes the event to the channels configured by the user.
func (p *PodInformer) notifyChans(key string) error {
	obj, exists, err := p.indexer.GetByKey(key)
	if err != nil {
		return fmt.Errorf("fetch object with key %s from store: %w", key, err)
	}
	defer p.queue.Forget(key)

	if !exists {
		p.deletedPodChan <- key
		return nil
	}

	pod, ok := obj.(*v1.Pod)
	if !ok {
		return fmt.Errorf("object with key %s is not a pod", key)
	}
	p.createdPodChan <- pod
	return nil
}

func (p *PodInformer) Run(threadiness int, stopCh chan struct{}) {
	defer runtime.HandleCrash()

	// Let the workers stop when we are done
	defer p.queue.ShutDown()
	level.Info(p.logger).Log("msg", "starting pod controller")

	go p.informer.Run(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, p.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	for i := 0; i < threadiness; i++ {
		go wait.Until(p.runWorker, time.Second, stopCh)
	}

	<-stopCh
	level.Info(p.logger).Log("msg", "stopping pod controller")
}

func (p *PodInformer) runWorker() {
	for p.processNextItem() {
	}
}
