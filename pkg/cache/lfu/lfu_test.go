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

package lfu

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestLFU(t *testing.T) {
	c := New[string, string](prometheus.NewRegistry())

	c.Add("a", "a")

	v, ok := c.Get("a")
	require.True(t, ok)
	require.Equal(t, "a", v)
	require.Equalf(t, 1, len(c.items), "expected len 1; got %d", len(c.items))

	c.Add("b", "b")

	v, ok = c.Get("b")
	require.True(t, ok)
	require.Equal(t, "b", v)
	require.Equalf(t, 2, len(c.items), "expected len 2; got %d", len(c.items))

	_, ok = c.Get("a")
	require.True(t, ok)

	c.Evict()
	_, ok = c.Get("a")
	require.Truef(t, ok, "value unexpectedly evicted")

	_, ok = c.Get("b")
	require.Falsef(t, ok, "value not evicted")

	require.Equalf(t, 1, len(c.items), "expected len 1; got %d", len(c.items))
}

func TestLFU_Add(t *testing.T) {
	l := New[int, int](prometheus.NewRegistry(), WithMaxSize[int, int](1))

	l.Add(1, 1)
	require.Equal(t, 0.0, testutil.ToFloat64(l.metrics.evictions))

	l.Add(2, 2)
	require.Equal(t, 1.0, testutil.ToFloat64(l.metrics.evictions))
}

func TestLFU_Peek(t *testing.T) {
	l := New[int, int](prometheus.NewRegistry(), WithMaxSize[int, int](3))

	l.Add(1, 1)
	l.Add(2, 2)
	l.Add(3, 3)

	_, ok := l.Get(3)
	require.True(t, ok)
	_, ok = l.Get(3)
	require.True(t, ok)
	_, ok = l.Get(3)
	require.True(t, ok)

	_, ok = l.Get(2)
	require.True(t, ok)
	_, ok = l.Get(2)
	require.True(t, ok)

	require.Equal(t, []int{3, 2, 1}, keyOrder(l))
}

func keyOrder[K comparable, V any](l *LFU[K, V]) []K {
	b := l.frequencyBuckets.Back()
	if b == nil {
		return nil
	}
	var keys []K
	for cb := b; cb != nil; cb = cb.Prev() {
		entries := cb.Value.(*frequencyBucket[K, V]).entries //nolint:forcetypeassert
		for e := range entries {
			keys = append(keys, e.key)
		}
	}
	return keys
}

func TestLFU_Remove(t *testing.T) {
	l := New[int, int](prometheus.NewRegistry(), WithMaxSize[int, int](2))

	l.Add(1, 1)
	l.Add(2, 2)
	l.Remove(1)
	if _, ok := l.Peek(1); ok {
		t.Errorf("1 should be removed")
	}
}
