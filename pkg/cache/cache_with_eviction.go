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
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache/lfu"
	"github.com/parca-dev/parca-agent/pkg/cache/lru"
)

// NewLRUWithEviction returns a new LRU cache with a given maximum size and eviction callback.
func NewLRUWithEviction[K comparable, V any](reg prometheus.Registerer, maxEntries int, onEvictedCallback func(k K, v V)) (*CacheWithEviction[K, V], error) {
	if onEvictedCallback == nil {
		return nil, errors.New("onEvictedCallback must not be nil")
	}
	c := &CacheWithEviction[K, V]{
		mtx: &sync.RWMutex{},
		onEvictedCallback: func(k K, v V) {
			onEvictedCallback(k, v)
		},
	}
	c.c = lru.New[K, V](
		reg,
		lru.WithMaxSize[K, V](maxEntries),
		lru.WithOnEvict[K, V](c.onEvicted),
	)
	return c, nil
}

// NewLFUWithEviction returns a new LFU cache with a given maximum size and eviction callback.
func NewLFUWithEviction[K comparable, V any](reg prometheus.Registerer, maxEntries int, onEvictedCallback func(k K, v V)) (*CacheWithEviction[K, V], error) {
	if onEvictedCallback == nil {
		return nil, errors.New("onEvictedCallback must not be nil")
	}
	c := &CacheWithEviction[K, V]{
		mtx: &sync.RWMutex{},
		onEvictedCallback: func(k K, v V) {
			onEvictedCallback(k, v)
		},
	}
	c.c = lfu.New[K, V](
		reg,
		lfu.WithMaxSize[K, V](maxEntries),
		lfu.WithOnEvict[K, V](c.onEvicted),
	)
	return c, nil
}

type CacheWithEviction[K comparable, V any] struct {
	c   cacher[K, V]
	mtx *sync.RWMutex

	onEvictedCallback func(k K, v V)
}

// onEvicted is called when an entry is evicted from the underlying LRU.
func (c *CacheWithEviction[K, V]) onEvicted(k K, v V) {
	c.onEvictedCallback(k, v)
}

// Add adds a value to the cache.
func (c *CacheWithEviction[K, V]) Add(key K, value V) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Add(key, value)
}

// Get looks up a key's value from the cache.
func (c *CacheWithEviction[K, V]) Get(key K) (V, bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.c.Get(key)
}

// Peek returns the value associated with key without updating the "recently used"-ness of that key.
func (c *CacheWithEviction[K, V]) Peek(key K) (V, bool) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.c.Peek(key)
}

// Remove removes the provided key from the cache.
func (c *CacheWithEviction[K, V]) Remove(key K) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Remove(key)
}

// Purge is used to completely clear the cache.
func (c *CacheWithEviction[K, V]) Purge() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Purge()
}

// Close is used to close the underlying LRU by also purging it.
func (c *CacheWithEviction[K, V]) Close() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.c.Close()
}
