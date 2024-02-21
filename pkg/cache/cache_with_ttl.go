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

//nolint:dupl
package cache

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache/lfu"
	"github.com/parca-dev/parca-agent/pkg/cache/lru"
)

// NewLRUCache returns a new concurrency-safe fixed size cache with LRU exiction policy and TTL.
func NewLRUCacheWithTTL[K comparable, V any](reg prometheus.Registerer, maxEntries int, ttl time.Duration, opts ...CacheWithTTLOptions) *CacheWithTTL[K, V] {
	lruOpts := []lru.Option[K, valueWithDeadline[V]]{
		lru.WithMaxSize[K, valueWithDeadline[V]](maxEntries),
	}
	c := &CacheWithTTL[K, V]{
		mtx: &sync.RWMutex{},
		ttl: ttl,
	}
	if len(opts) > 0 {
		c.updateDeadlineOnGet = opts[0].UpdateDeadlineOnGet
		c.removeExpiredOnAdd = opts[0].RemoveExpiredOnAdd
		if c.removeExpiredOnAdd {
			c.nextRemoveExpired = time.Now().Add(ttl)
			lruOpts = append(lruOpts, lru.WithOnAdded[K, valueWithDeadline[V]](func(key K, value valueWithDeadline[V]) {
				now := time.Now()
				if c.nextRemoveExpired.Before(now) {
					// Happens in "Add" inside a lock, so we don't need to lock here.
					c.c.RemoveMatching(func(k K, v valueWithDeadline[V]) bool {
						return v.deadline.Before(now)
					})
					c.nextRemoveExpired = now.Add(ttl)
				}
			}))
		}
	}
	c.c = lru.New[K, valueWithDeadline[V]](reg, lruOpts...)
	return c
}

// NewLFUCacheWithTTL returns a new concurrency-safe fixed size cache with LFU exiction policy and TTL.
func NewLFUCacheWithTTL[K comparable, V any](reg prometheus.Registerer, maxEntries int, ttl time.Duration, opts ...CacheWithTTLOptions) *CacheWithTTL[K, V] {
	lfuOpts := []lfu.Option[K, valueWithDeadline[V]]{
		lfu.WithMaxSize[K, valueWithDeadline[V]](maxEntries),
	}
	c := &CacheWithTTL[K, V]{
		mtx: &sync.RWMutex{},
		ttl: ttl,
	}
	if len(opts) > 0 {
		c.updateDeadlineOnGet = opts[0].UpdateDeadlineOnGet
		c.removeExpiredOnAdd = opts[0].RemoveExpiredOnAdd
		if c.removeExpiredOnAdd {
			c.nextRemoveExpired = time.Now().Add(ttl)
			lfuOpts = append(lfuOpts, lfu.WithOnAdded[K, valueWithDeadline[V]](func(key K, value valueWithDeadline[V]) {
				now := time.Now()
				if c.nextRemoveExpired.Before(now) {
					// Happens in "Add" inside a lock, so we don't need to lock here.
					c.c.RemoveMatching(func(k K, v valueWithDeadline[V]) bool {
						return v.deadline.Before(now)
					})
					c.nextRemoveExpired = now.Add(ttl)
				}
			}))
		}
	}
	c.c = lfu.New[K, valueWithDeadline[V]](reg, lfuOpts...)
	return c
}

type cacherWithRemoveMatching[K comparable, V any] interface {
	cacher[K, V]
	RemoveMatching(predicate func(key K, value V) bool)
}

type CacheWithTTLOptions struct {
	UpdateDeadlineOnGet bool
	RemoveExpiredOnAdd  bool
}

type valueWithDeadline[V any] struct {
	value    V
	deadline time.Time
}

type CacheWithTTL[K comparable, V any] struct {
	c   cacherWithRemoveMatching[K, valueWithDeadline[V]]
	mtx *sync.RWMutex

	ttl time.Duration

	updateDeadlineOnGet bool
	removeExpiredOnAdd  bool
	nextRemoveExpired   time.Time
}

func (c *CacheWithTTL[K, V]) Add(key K, value V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Add(key, valueWithDeadline[V]{
		value:    value,
		deadline: time.Now().Add(c.ttl),
	})
}

func (c *CacheWithTTL[K, V]) Get(key K) (V, bool) {
	c.mtx.Lock()
	v, ok := c.c.Get(key)
	c.mtx.Unlock()
	if !ok {
		return v.value, false
	}
	if v.deadline.Before(time.Now()) {
		c.mtx.Lock()
		c.c.Remove(key)
		c.mtx.Unlock()
		return v.value, false
	}
	if c.updateDeadlineOnGet {
		c.mtx.Lock()
		c.c.Add(key, valueWithDeadline[V]{
			value:    v.value,
			deadline: time.Now().Add(c.ttl),
		})
		c.mtx.Unlock()
	}
	return v.value, true
}

func (c *CacheWithTTL[K, V]) Peek(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	v, ok := c.c.Peek(key)
	return v.value, ok
}

func (c *CacheWithTTL[K, V]) Remove(key K) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Remove(key)
}

func (c *CacheWithTTL[K, V]) Purge() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Purge()
}

func (c *CacheWithTTL[K, V]) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.c.Close()
}

// NewLRUCacheWithEvictionTTL returns a new concurrency-safe fixed size cache with LRU exiction policy, TTL and eviction callback.
func NewLRUCacheWithEvictionTTL[K comparable, V any](reg prometheus.Registerer, maxEntries int, ttl time.Duration, onEvictedCallback func(k K, v V)) *CacheWithEvictionTTL[K, V] {
	opts := []lru.Option[K, valueWithDeadline[V]]{
		lru.WithMaxSize[K, valueWithDeadline[V]](maxEntries),
		lru.WithOnEvict[K, valueWithDeadline[V]](func(k K, vd valueWithDeadline[V]) {
			onEvictedCallback(k, vd.value)
		}),
	}
	return &CacheWithEvictionTTL[K, V]{
		c:   lru.New[K, valueWithDeadline[V]](reg, opts...),
		mtx: &sync.RWMutex{},
		ttl: ttl,
	}
}

// NewLFUCacheWithEvictionTTL returns a new concurrency-safe fixed size cache with LFU exiction policy, TTL and eviction callback.
func NewLFUCacheWithEvictionTTL[K comparable, V any](reg prometheus.Registerer, maxEntries int, ttl time.Duration, onEvictedCallback func(k K, v V)) *CacheWithEvictionTTL[K, V] {
	opts := []lfu.Option[K, valueWithDeadline[V]]{
		lfu.WithMaxSize[K, valueWithDeadline[V]](maxEntries),
		lfu.WithOnEvict[K, valueWithDeadline[V]](func(k K, vd valueWithDeadline[V]) {
			onEvictedCallback(k, vd.value)
		}),
	}
	return &CacheWithEvictionTTL[K, V]{
		c:   lfu.New[K, valueWithDeadline[V]](reg, opts...),
		mtx: &sync.RWMutex{},
		ttl: ttl,
	}
}

type CacheWithEvictionTTL[K comparable, V any] struct {
	c   cacherWithRemoveMatching[K, valueWithDeadline[V]]
	mtx *sync.RWMutex

	ttl time.Duration
}

func (c *CacheWithEvictionTTL[K, V]) Add(key K, value V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Add(key, valueWithDeadline[V]{
		value:    value,
		deadline: time.Now().Add(c.ttl),
	})
}

func (c *CacheWithEvictionTTL[K, V]) Get(key K) (V, bool) {
	c.mtx.Lock()
	v, ok := c.c.Get(key)
	c.mtx.Unlock()
	if !ok {
		var zero V
		return zero, false
	}
	if v.deadline.Before(time.Now()) {
		c.mtx.Lock()
		c.c.Remove(key)
		c.mtx.Unlock()
		var zero V
		return zero, false
	}
	return v.value, true
}

func (c *CacheWithEvictionTTL[K, V]) Peek(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	v, ok := c.c.Peek(key)
	return v.value, ok
}

func (c *CacheWithEvictionTTL[K, V]) Remove(key K) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Remove(key)
}

func (c *CacheWithEvictionTTL[K, V]) Purge() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Purge()
}

func (c *CacheWithEvictionTTL[K, V]) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.c.Close()
}
