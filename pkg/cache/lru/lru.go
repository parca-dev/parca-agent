package lru

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type LRU[K comparable, V any] struct {
	hits, misses, evictions prometheus.Counter

	maxEntries int
	items      map[K]*entry[K, V]
	evictList  *lruList[K, V]
}

func New[K comparable, V any](reg prometheus.Registerer, maxEntries int) *LRU[K, V] {
	requests := promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
		Name: "cache_requests_total",
		Help: "Total number of cache requests.",
	}, []string{"result"})

	c := &LRU[K, V]{
		hits:   requests.WithLabelValues("hit"),
		misses: requests.WithLabelValues("miss"),
		evictions: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "cache_evictions_total",
			Help: "Total number of cache evictions.",
		}),

		maxEntries: maxEntries,
		evictList:  newList[K, V](),
		items:      map[K]*entry[K, V]{},
	}
	return c
}

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

func (c *LRU[K, V]) Remove(key K) {
	if ent, ok := c.items[key]; ok {
		c.removeElement(ent)
	}
}

func (c *LRU[K, V]) Get(key K) (value V, ok bool) {
	if ent, ok := c.items[key]; ok {
		c.evictList.moveToFront(ent)
		c.hits.Inc()
		return ent.value, true
	}
	c.misses.Inc()
	return
}

func (c *LRU[K, V]) Peek(key K) (value V, ok bool) {
	if ent, ok := c.items[key]; ok {
		return ent.value, true
	}
	return
}

// removeOldest removes the oldest item from the cache.
func (c *LRU[K, V]) removeOldest() {
	if ent := c.evictList.back(); ent != nil {
		c.removeElement(ent)
	}
}

// removeElement is used to remove a given list element from the cache
func (c *LRU[K, V]) removeElement(e *entry[K, V]) {
	c.evictList.remove(e)
	delete(c.items, e.key)
}
