// Copyright 2022-2023 The Parca Authors
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
//

package namespace

import (
	"io/fs"
	"os"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
)

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

type Cache struct {
	c *cache.LoadingLRUCacheWithTTL[int, []int]
}

func NewCache(logger log.Logger, reg prometheus.Registerer, profilingDuration time.Duration) *Cache {
	return &Cache{
		cache.NewLoadingLRUCacheWithTTL[int, []int](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "process_namespace"}, reg),
			512,                  // cache size.
			10*profilingDuration, // cache TTL.
			func(pid int) ([]int, error) {
				return FindPIDs(&realfs{}, pid)
			},
		),
	}
}

func (c *Cache) Get(key int) ([]int, error) {
	return c.c.Get(key)
}
