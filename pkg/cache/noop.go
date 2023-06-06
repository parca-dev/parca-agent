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

import burrow "github.com/goburrow/cache"

type noopCache[K comparable, V any] struct{}

func NewNoopCache[K comparable, V any]() *noopCache[K, V] {
	return &noopCache[K, V]{}
}

func (c *noopCache[K, V]) Add(key K, value V) {
}

func (c *noopCache[K, V]) Get(key K) (V, bool) {
	var zero V
	return zero, false
}

func (c *noopCache[K, V]) Peek(key K) (V, bool) {
	var zero V
	return zero, false
}

func (c *noopCache[K, V]) Remove(key K) {
}

var _ burrow.Cache = (*burrowNoopCache)(nil)

// burrowNoopCache implements the burrow.Cache interface but does not cache anything.
// It is useful for testing, so let's keep it around.
type burrowNoopCache struct{}

func NewBurrowNoopCache() *burrowNoopCache {
	return &burrowNoopCache{}
}

func (c *burrowNoopCache) GetIfPresent(burrow.Key) (burrow.Value, bool) {
	return nil, false
}

func (c *burrowNoopCache) Put(burrow.Key, burrow.Value) {
}

func (c *burrowNoopCache) Invalidate(burrow.Key) {
}

func (c *burrowNoopCache) InvalidateAll() {
}

func (c *burrowNoopCache) Stats(*burrow.Stats) {
}

func (c *burrowNoopCache) Close() error {
	return nil
}
