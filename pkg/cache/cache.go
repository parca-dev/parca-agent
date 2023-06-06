package cache

import (
	"sync"

	"github.com/parca-dev/parca-agent/pkg/cache/lru"
	"github.com/prometheus/client_golang/prometheus"
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
