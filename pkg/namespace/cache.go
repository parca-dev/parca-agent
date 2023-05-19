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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/go-kit/log"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
)

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

type Cache struct {
	burrow.LoadingCache
}

func NewCache(logger log.Logger, reg prometheus.Registerer, profilingDuration time.Duration) *Cache {
	return &Cache{
		cache.NewLoadingOnceCache(
			func(key burrow.Key) (burrow.Value, error) {
				k, ok := key.(int)
				if !ok {
					return nil, errors.New("invalid key type")
				}
				return FindPIDs(&realfs{}, k)
			},
			burrow.WithMaximumSize(512),
			burrow.WithExpireAfterAccess(10*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "process_namespace")),
		),
	}
}

func (c *Cache) Get(key int) ([]int, error) {
	v, err := c.LoadingCache.Get(key)
	if err != nil {
		return nil, err
	}
	val, ok := v.([]int)
	if !ok {
		return nil, fmt.Errorf("unexpected type in cache: %T", val)
	}
	return val, nil
}
