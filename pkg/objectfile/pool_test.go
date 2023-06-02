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

// nolint:wastedassign,dupl
package objectfile

import (
	"runtime"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestPoolWithFinalizer(t *testing.T) {
	expirationUnitDuration := 200 * time.Millisecond

	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), expirationUnitDuration)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj1, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)
	buildID1 := obj1.BuildID

	obj2, err := objPool.Open("./testdata/fib-nopie")
	require.NoError(t, err)
	buildID2 := obj2.BuildID

	obj3, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)
	require.NotNil(t, obj3)

	obj4, err := objPool.Open("./testdata/fib-nopie")
	require.NoError(t, err)
	require.NotNil(t, obj4)

	// Underlying files should be the same.
	require.Equal(t, obj1.elf, obj3.elf)
	require.Equal(t, obj2.elf, obj4.elf)

	obj2 = nil   // Remove reference to obj2.
	obj3 = nil   // Remove reference to obj3.
	obj4 = nil   // Remove reference to obj4.
	runtime.GC() // Force GC, so finalizers are called.

	// obj1 should still be in the pool.
	cachedObj, err := objPool.get(buildID1)
	require.NoError(t, err)
	require.NotNil(t, cachedObj)

	// Wait for object pool to expire all objects.
	time.Sleep(keepAliveProfileCycle * expirationUnitDuration)

	// obj1 should be released.
	v, err := objPool.get(buildID1)
	require.Nil(t, v)
	require.Error(t, err)

	// obj2 should be released.
	_, err = objPool.get(buildID2)
	require.Error(t, err)

	// obj1 should still be accessible.
	require.NotNil(t, obj1)

	// There should be 2 unique objects in the pool.
	require.Equal(t, 2.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 3.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	// There should be only 1 close attempt. Because obj1 still has a reference.
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))

	runtime.GC() // Force GC, so finalizers are called.

	// obj1 should be released.
	require.Equal(t, 2.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 2.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))

	t.Log(objPool.stats())
}

func TestObjectFileLifeCycleELF(t *testing.T) {
	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), time.Millisecond)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release := doSomethingWithELF(obj)
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release()
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
}

func TestObjectFileLifeCycleELFAsync(t *testing.T) {
	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), time.Millisecond)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	done := make(chan struct{})
	go func() {
		defer close(done)

		release := doSomethingWithELF(obj)
		release()

		runtime.GC() // Force GC, so finalizers are called.
	}()

	runtime.GC() // Force GC, so finalizers are called.
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release := doSomethingWithELF(obj)
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	<-done
	release()

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
}

func doSomethingWithELF(obj *ObjectFile) func() {
	ef, release, err := obj.ELF()
	if err != nil {
		panic(err)
	}
	_ = ef
	return release
}

func TestObjectFileLifeCycleReaderWithRelease(t *testing.T) {
	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), time.Millisecond)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release := doSomethingWithReader(obj)
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release()
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
}

func TestObjectFileLifeCycleReaderAsyncJoin(t *testing.T) {
	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), time.Millisecond)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		// This should block until the reader is released.
		obj1, err := objPool.Open("./testdata/fib")
		require.NoError(t, err)

		<-start
		require.Equal(t, obj, obj1)
	}()

	runtime.GC() // Force GC, so finalizers are called.
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release := doSomethingWithReader(obj)
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release()
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	close(start)
	<-done
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
}

func TestObjectFileLifeCycleReaderAsync(t *testing.T) {
	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), time.Millisecond)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	done := make(chan struct{})
	go func() {
		defer close(done)

		release := doSomethingWithReader(obj)
		release()

		runtime.GC() // Force GC, so finalizers are called.
	}()

	runtime.GC() // Force GC, so finalizers are called.
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	release := doSomethingWithReader(obj)
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	<-done
	release()

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
}

func doSomethingWithReader(obj *ObjectFile) func() {
	r, release, err := obj.Reader()
	if err != nil {
		panic(err)
	}
	// defer release()
	_ = r
	return release
}

func TestObjectFileLifeCycleHoldOn(t *testing.T) {
	// On a slow filessystem, the test may fail because the cache expiration.
	objPool := NewPool(log.NewNopLogger(), prometheus.NewRegistry(), time.Millisecond)
	t.Cleanup(func() {
		// There should be root references to release.
		require.NoError(t, objPool.Close())
	})

	obj, err := objPool.Open("./testdata/fib")
	require.NoError(t, err)

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvSuccess)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.opened.WithLabelValues(lvShared)))

	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))

	doSomethingWithHoldOn(obj)
	runtime.GC() // Force GC, so finalizers are called.

	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closeAttempts))
	require.Equal(t, 0.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvError)))
	require.Equal(t, 1.0, testutil.ToFloat64(objPool.metrics.closed.WithLabelValues(lvSuccess)))
}

func doSomethingWithHoldOn(obj *ObjectFile) {
	defer obj.HoldOn()
}
