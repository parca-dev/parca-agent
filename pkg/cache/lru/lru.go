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

package lru

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type LRU[K comparable, V any] struct {
	hits, misses, evictions prometheus.Counter

	maxEntries int
	items      map[K]*entry[K, V]
	evictList  *lruList[K, V]

	closer func() error
}

func New[K comparable, V any](reg prometheus.Registerer, maxEntries int) *LRU[K, V] {
	requests := promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
		Name: "cache_requests_total",
		Help: "Total number of cache requests.",
	}, []string{"result"})
	evictions := promauto.With(reg).NewCounter(prometheus.CounterOpts{
		Name: "cache_evictions_total",
		Help: "Total number of cache evictions.",
	})

	c := &LRU[K, V]{
		hits:      requests.WithLabelValues("hit"),
		misses:    requests.WithLabelValues("miss"),
		evictions: evictions,

		maxEntries: maxEntries,
		evictList:  newList[K, V](),
		items:      map[K]*entry[K, V]{},
		closer: func() error {
			// This closer makes sure that the metrics are unregistered when the cache is closed.
			// This is useful when the a new cache is created with the same name.
			var err error
			if ok := reg.Unregister(requests); !ok {
				err = errors.Join(err, fmt.Errorf("unregistering requests counter: %w", err))
			}
			if ok := reg.Unregister(evictions); !ok {
				err = errors.Join(err, fmt.Errorf("unregistering eviction counter: %w", err))
			}
			if err != nil {
				return fmt.Errorf("cleaning cache stats counter: %w", err)
			}
			return nil
		},
	}
	return c
}

// Add adds a value to the cache.
func (c *LRU[K, V]) Add(key K, value V) {
	if entry, ok := c.items[key]; ok {
		c.evictList.moveToFront(entry)
		entry.value = value
		return
	}

	entry := c.evictList.pushFront(key, value)
	c.items[key] = entry

	// Should evict?
	if c.evictList.length() > c.maxEntries {
		c.removeOldest()
		c.evictions.Inc()
	}
}

// Remove removes a key from the cache.
func (c *LRU[K, V]) Remove(key K) {
	if ent, ok := c.items[key]; ok {
		c.removeElement(ent)
	}
}

// Get retrieves an item from the cache.
// Return (value, true) if the item is found, and false otherwise.
func (c *LRU[K, V]) Get(key K) (value V, ok bool) { //nolint:nonamedreturns
	if ent, ok := c.items[key]; ok {
		c.evictList.moveToFront(ent)
		c.hits.Inc()
		return ent.value, true
	}
	c.misses.Inc()
	return
}

// Peek returns the value associated with the key without updating the LRU order.
// Returns (value, true) if the item is found, and false otherwise.
func (c *LRU[K, V]) Peek(key K) (value V, ok bool) { //nolint:nonamedreturns
	if ent, ok := c.items[key]; ok {
		return ent.value, true
	}
	return
}

// Purge is used to completely clear the cache.
func (c *LRU[K, V]) Purge() {
	for k := range c.items {
		delete(c.items, k)
	}
	c.evictList.init()
}

// Close is used when the cache is not needed anymore.
func (c *LRU[K, V]) Close() error {
	c.Purge()
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

// removeOldest removes the oldest item from the cache.
func (c *LRU[K, V]) removeOldest() {
	if ent := c.evictList.back(); ent != nil {
		c.removeElement(ent)
	}
}

// removeElement is used to remove a given list element from the cache.
func (c *LRU[K, V]) removeElement(e *entry[K, V]) {
	c.evictList.remove(e)
	delete(c.items, e.key)
}
