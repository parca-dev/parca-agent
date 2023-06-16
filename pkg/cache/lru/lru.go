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
	"github.com/prometheus/client_golang/prometheus"
)

type LRU[K comparable, V any] struct {
	metrics *metrics

	maxEntries int
	items      map[K]*entry[K, V]
	evictList  *lruList[K, V]

	closer func() error
}

func New[K comparable, V any](reg prometheus.Registerer, maxEntries int) *LRU[K, V] {
	m := newMetrics(reg)
	c := &LRU[K, V]{
		metrics: m,
		closer:  m.unregister,

		maxEntries: maxEntries,
		evictList:  newList[K, V](),
		items:      map[K]*entry[K, V]{},
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

	if c.maxEntries != 0 && c.evictList.length() > c.maxEntries {
		c.removeOldest()
		c.metrics.evictions.Inc()
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
		c.metrics.hits.Inc()
		return ent.value, true
	}
	c.metrics.misses.Inc()
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
