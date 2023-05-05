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

import (
	"fmt"

	"github.com/goburrow/cache"
	"golang.org/x/sync/singleflight"
)

// NewLoadingOnceCache creates a LoadingCache that allows only one loading operation at a time.
//
// The returned LoadingCache will call the loader function to load entries
// on cache misses. However, it will use a singleflight.Group to ensure only
// one concurrent call to the loader is made for a given key. This can be used
// to prevent redundant loading of data on cache misses when multiple concurrent
// requests are made for the same key.
func NewLoadingOnceCache(loader cache.LoaderFunc, options ...cache.Option) cache.LoadingCache {
	sfg := &singleflight.Group{}
	onceLoader := func(k cache.Key) (cache.Value, error) {
		// Singleflight key must be string.
		// And cache.Key is interface{}, so we need to convert it to string.
		var key string
		if v, ok := k.(string); ok {
			key = v
		} else {
			key = fmt.Sprintf("%v", k)
		}
		// singleflight.Group memoizes the return value of the first call and returns it.
		// The 3rd return value is true if multiple calls happens simultaneously,
		// and the caller received the value from the first call.
		val, err, _ := sfg.Do(key, func() (interface{}, error) {
			return loader(k)
		})
		return val, err
	}
	return cache.NewLoadingCache(onceLoader, options...)
}
