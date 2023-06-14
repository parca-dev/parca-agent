// Copyright 2023 The Parca Authors
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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache/lru"
)

type LRUCache[K comparable, V any] struct {
	lru *lru.LRU[K, V]
	mtx *sync.RWMutex
}

func NewLRUCache[K comparable, V any](reg prometheus.Registerer, maxEntries int) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		lru: lru.New[K, V](reg, maxEntries),
		mtx: &sync.RWMutex{},
	}
}

func (c *LRUCache[K, V]) Add(key K, value V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lru.Add(key, value)
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.lru.Get(key)
}

// Peek returns the value associated with key without updating the "recently
// used"-ness of that key.
func (c *LRUCache[K, V]) Peek(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.lru.Peek(key)
}

func (c *LRUCache[K, V]) Remove(key K) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lru.Remove(key)
}

func (c *LRUCache[K, V]) Purge() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lru.Purge()
}

func (c *LRUCache[K, V]) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.lru.Purge()
	return c.lru.Close()
}

type LRUCacheWithTTL[K comparable, V any] struct {
	lru *lru.LRU[K, valueWithDeadline[V]]
	mtx *sync.RWMutex

	ttl time.Duration
}

type valueWithDeadline[V any] struct {
	value    V
	deadline time.Time
}

func NewLRUCacheWithTTL[K comparable, V any](reg prometheus.Registerer, maxEntries int, ttl time.Duration) *LRUCacheWithTTL[K, V] {
	return &LRUCacheWithTTL[K, V]{
		lru: lru.New[K, valueWithDeadline[V]](reg, maxEntries),
		mtx: &sync.RWMutex{},
		ttl: ttl,
	}
}

func (c *LRUCacheWithTTL[K, V]) Add(key K, value V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lru.Add(key, valueWithDeadline[V]{
		value:    value,
		deadline: time.Now().Add(c.ttl),
	})
}

func (c *LRUCacheWithTTL[K, V]) Get(key K) (V, bool) {
	c.mtx.RLock()
	v, ok := c.lru.Get(key)
	c.mtx.RUnlock()
	if !ok {
		return v.value, false
	}
	if v.deadline.Before(time.Now()) {
		c.mtx.Lock()
		c.lru.Remove(key)
		c.mtx.Unlock()
		return v.value, false
	}
	return v.value, true
}

func (c *LRUCacheWithTTL[K, V]) Peek(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	v, ok := c.lru.Peek(key)
	return v.value, ok
}

func (c *LRUCacheWithTTL[K, V]) Remove(key K) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lru.Remove(key)
}

func (c *LRUCacheWithTTL[K, V]) Purge() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.lru.Purge()
}

func (c *LRUCacheWithTTL[K, V]) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.lru.Close()
}
