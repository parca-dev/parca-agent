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

var _ burrow.Cache = (*noopCache)(nil)

// noopCache implements the burrow.Cache interface but does not cache anything.
// It is useful for testing, so let's keep it around.
type noopCache struct{}

func NewNoopCache() *noopCache {
	return &noopCache{}
}

func (c *noopCache) GetIfPresent(burrow.Key) (burrow.Value, bool) {
	return nil, false
}

func (c *noopCache) Put(burrow.Key, burrow.Value) {
}

func (c *noopCache) Invalidate(burrow.Key) {
}

func (c *noopCache) InvalidateAll() {
}

func (c *noopCache) Stats(*burrow.Stats) {
}

func (c *noopCache) Close() error {
	return nil
}
