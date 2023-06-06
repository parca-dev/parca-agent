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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLRUCache(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewLRUCache[string, int](reg, 2)

	c.Add("key1", 1)
	c.Add("key2", 2)

	v, ok := c.Get("key1")
	if !ok || v != 1 {
		t.Errorf("expected to get key1 = 1, got %v, %v", v, ok)
	}

	v, ok = c.Peek("key2")
	if !ok || v != 2 {
		t.Errorf("expected to peek key2 = 2, got %v, %v", v, ok)
	}

	c.Add("key3", 3)

	_, ok = c.Get("key2")
	if ok {
		t.Errorf("expected key1 to be evicted, but was still present")
	}

	c.Remove("key1")
	_, ok = c.Peek("key2")
	if ok {
		t.Errorf("expected key2 to be removed, but was still present")
	}
}

func TestLRUCacheWithTTL(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewLRUCacheWithTTL[string, int](reg, 2, 1*time.Millisecond)

	c.Add("key1", 1)
	v, ok := c.Get("key1")
	if !ok || v != 1 {
		t.Errorf("expected value 1 for key1, got %v", v)
	}

	time.Sleep(2 * time.Millisecond)
	_, ok = c.Get("key1")
	if ok {
		t.Errorf("expected key1 to expire")
	}

	c.Add("key2", 2)
	v, ok = c.Peek("key2")
	if !ok || v != 2 {
		t.Errorf("expected value 2 for key2, got %v", v)
	}
	v, ok = c.Get("key2")
	if !ok || v != 2 {
		t.Errorf("expected value 2 for key2, got %v", v)
	}
	c.Add("key3", 3)

	v, ok = c.Peek("key2")
	if !ok || v != 2 {
		t.Errorf("expected value 2 for key2, got %v", v)
	}

	c.Remove("key2")
	_, ok = c.Get("key2")
	if ok {
		t.Errorf("expected key2 to be removed")
	}

	c.Add("key4", 4)
	c.Add("key5", 5)

	_, ok = c.Get("key3")
	if ok {
		t.Errorf("expected key3 to be evicted, but was still present")
	}
}
