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

// nolint:forcetypeassert
package lfu

import (
	"container/list"

	"github.com/prometheus/client_golang/prometheus"
)

type entry[K comparable, V any] struct {
	key        K
	value      V
	freqBucket *list.Element
}

type frequencyBucket[K comparable, V any] struct {
	freq    uint
	entries map[*entry[K, V]]struct{}
}

func (b *frequencyBucket[K, V]) removeEntry(e *entry[K, V]) {
	delete(b.entries, e)
	if len(b.entries) == 0 {
		b.entries = nil
	}
}

// LFU is a thread-safe fixed size LFU cache.
type LFU[K comparable, V any] struct {
	metrics *metrics
	closer  func() error

	maxEntries int // Zero means no limit.
	onEvicted  func(K, V)
	onAdded    func(K, V)

	frequencyBuckets *list.List // of *frequencyBucket[K, V]
	items            map[K]*entry[K, V]
}

func New[K comparable, V any](reg prometheus.Registerer, opts ...Option[K, V]) *LFU[K, V] {
	m := newMetrics(reg)

	lfu := &LFU[K, V]{
		metrics: m,
		closer:  m.unregister,

		frequencyBuckets: list.New(),
		items:            make(map[K]*entry[K, V]),
	}

	for _, opt := range opts {
		opt(lfu)
	}
	return lfu
}

func (c *LFU[K, V]) increment(e *entry[K, V]) {
	var (
		freq       uint
		nextBucket *list.Element

		currentBucket = e.freqBucket
	)
	if currentBucket == nil {
		// New entry, add to the first bucket.
		freq = 1
		nextBucket = c.frequencyBuckets.Front()
	} else {
		// Existing entry, increment frequency and move to the next bucket.
		freq = currentBucket.Value.(*frequencyBucket[K, V]).freq + 1
		nextBucket = currentBucket.Next()
	}

	if nextBucket == nil || nextBucket.Value.(*frequencyBucket[K, V]).freq != freq {
		// Bucket doesn't exist, create it.
		newBucket := &frequencyBucket[K, V]{freq: freq, entries: make(map[*entry[K, V]]struct{})}
		if currentBucket != nil {
			// Insert after the current bucket.
			nextBucket = c.frequencyBuckets.InsertAfter(newBucket, currentBucket)
		} else {
			// Insert at the front.
			nextBucket = c.frequencyBuckets.PushFront(newBucket)
		}
	}

	// Move the entry to the new bucket.
	e.freqBucket = nextBucket
	nextBucket.Value.(*frequencyBucket[K, V]).entries[e] = struct{}{}

	// Remove the entry from the old bucket.
	if currentBucket != nil {
		b := currentBucket.Value.(*frequencyBucket[K, V])
		b.removeEntry(e)
		if len(b.entries) == 0 {
			c.frequencyBuckets.Remove(currentBucket)
		}
	}
}

// Add adds a value to the cache.
func (c *LFU[K, V]) Add(key K, value V) {
	if e, ok := c.items[key]; ok {
		// Value already exists, update frequency.
		e.value = value
		c.increment(e)
		return
	}

	// Value doesn't exist, add it.
	e := &entry[K, V]{key, value, nil}
	c.items[key] = e
	c.increment(e)

	if c.maxEntries != 0 && len(c.items) > c.maxEntries {
		c.removeLeastFrequent()
	}

	if c.onAdded != nil {
		c.onAdded(key, value)
	}
}

// Get looks up a key's value from the cache.
func (c *LFU[K, V]) Get(key K) (value V, ok bool) { //nolint:nonamedreturns
	if e, ok := c.items[key]; ok {
		c.increment(e)
		c.metrics.hits.Inc()
		return e.value, true
	}
	c.metrics.misses.Inc()
	return
}

// Peek looks up a key's value from the cache without updating the frequency.
func (c *LFU[K, V]) Peek(key K) (value V, ok bool) { //nolint:nonamedreturns
	if e, ok := c.items[key]; ok {
		return e.value, true
	}
	return
}

// Evict one element from the cache depending on the eviction policy.
func (c *LFU[K, V]) Evict() {
	c.removeLeastFrequent()
}

// Remove removes the provided key from the cache.
func (c *LFU[K, V]) Remove(key K) {
	if e, ok := c.items[key]; ok {
		c.removeEntry(e)
	}
}

// removeEntry removes the provided entry from the cache and removes the corresponding bucket if empty.
func (c *LFU[K, V]) removeEntry(e *entry[K, V]) {
	delete(c.items, e.key)
	if c.onEvicted != nil {
		c.onEvicted(e.key, e.value)
	}
	c.metrics.evictions.Inc()

	bucket := e.freqBucket.Value.(*frequencyBucket[K, V])
	bucket.removeEntry(e)
	if len(bucket.entries) == 0 {
		c.frequencyBuckets.Remove(e.freqBucket)
	}
}

func (c *LFU[K, V]) removeLeastFrequent() {
	if bucket := c.frequencyBuckets.Front(); bucket != nil {
		for entry := range bucket.Value.(*frequencyBucket[K, V]).entries {
			if entry != nil {
				c.removeEntry(entry)
				return
			}
		}
	}
}

// Purge is used to completely clear the cache.
func (c *LFU[K, V]) Purge() {
	for k, e := range c.items {
		if c.onEvicted != nil {
			c.onEvicted(k, e.value)
		}
		delete(c.items, k)
	}
	c.frequencyBuckets.Init()
}

// Close closes the cache and unregisters the metrics.
func (c *LFU[K, V]) Close() error {
	c.Purge()
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

// RemoveMatching removes items from the cache that match the predicate.
func (c *LFU[K, V]) RemoveMatching(predicate func(key K, value V) bool) {
	for k, e := range c.items {
		if predicate(k, e.value) {
			c.removeEntry(e)
		}
	}
}
