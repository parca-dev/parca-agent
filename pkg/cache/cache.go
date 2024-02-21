// Copyright 2023-2024 The Parca Authors
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

package cache

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache/lfu"
	"github.com/parca-dev/parca-agent/pkg/cache/lru"
)

// NewLRUCache returns a new concurrency-safe fixed size cache with LRU exiction policy.
func NewLRUCache[K comparable, V any](reg prometheus.Registerer, maxEntries int) *Cache[K, V] {
	return &Cache[K, V]{
		c:   lru.New[K, V](reg, lru.WithMaxSize[K, V](maxEntries)),
		mtx: &sync.RWMutex{},
	}
}

// NewLFUCache returns a new concurrency-safe fixed size cache with LFU exiction policy.
func NewLFUCache[K comparable, V any](reg prometheus.Registerer, maxEntries int) *Cache[K, V] {
	return &Cache[K, V]{
		c:   lfu.New[K, V](reg, lfu.WithMaxSize[K, V](maxEntries)),
		mtx: &sync.RWMutex{},
	}
}

type cacher[K comparable, V any] interface {
	Add(key K, value V)
	Get(key K) (V, bool)
	Peek(key K) (V, bool)
	Remove(key K)
	Purge()
	Close() error
}

type Cache[K comparable, V any] struct {
	c   cacher[K, V]
	mtx *sync.RWMutex
}

func (c *Cache[K, V]) Add(key K, value V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Add(key, value)
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.c.Get(key)
}

// Peek returns the value associated with key without updating the "recently used"-ness of that key.
func (c *Cache[K, V]) Peek(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.c.Peek(key)
}

func (c *Cache[K, V]) Remove(key K) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Remove(key)
}

func (c *Cache[K, V]) Purge() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Purge()
}

func (c *Cache[K, V]) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.c.Purge()
	return c.c.Close()
}
