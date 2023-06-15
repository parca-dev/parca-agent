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
	key1 := cacheKeyFromObject(obj1)

	obj2, err := objPool.Open("./testdata/fib-nopie")
	require.NoError(t, err)
	key2 := cacheKeyFromObject(obj2)

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
	cachedObj, err := objPool.get(key1)
	require.NoError(t, err)
	require.NotNil(t, cachedObj)

	// Wait for object pool to expire all objects.
	time.Sleep(keepAliveProfileCycle * expirationUnitDuration)

	// obj1 should be released.
	v, err := objPool.get(key1)
	require.Nil(t, v)
	require.Error(t, err)

	// obj2 should be released.
	_, err = objPool.get(key2)
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

func TestRemoveProcPrefix(t *testing.T) {
	// - (for extracted debuginfo) /tmp/<buildid>
	// - (for found debuginfo) /usr/lib/debug/.build-id/<2-char>/<buildid>.debug
	// - (for running processes) /proc/123/root/usr/bin/parca-agent
	// - (for shared libraries) /proc/123/root/usr/lib/libc.so.6
	// - (for singleton objects) /usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so
	tests := []struct {
		name     string
		path     string
		wantPath string
	}{
		{
			name:     "remove /proc/<pid>/root prefix",
			path:     "/proc/123/root/exe",
			wantPath: "/exe",
		},
		{
			name:     "kepp /proc/<pid>/ prefix",
			path:     "/proc/1234/cwd",
			wantPath: "/proc/1234/cwd",
		},
		{
			name:     "keep path intact if no match",
			path:     "/bin/bash",
			wantPath: "/bin/bash",
		},
		{
			name:     "shared libraries",
			path:     "/proc/123/root/usr/lib/libc.so.6",
			wantPath: "/usr/lib/libc.so.6",
		},
		{
			name:     "extracted debuginfo",
			path:     "/tmp/1234",
			wantPath: "/tmp/1234",
		},
		{
			name:     "found debuginfo",
			path:     "/usr/lib/debug/.build-id/12/1234.debug",
			wantPath: "/usr/lib/debug/.build-id/12/1234.debug",
		},
		{
			name:     "singleton objects",
			path:     "/usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so",
			wantPath: "/usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath := removeProcPrefix(tt.path)
			if gotPath != tt.wantPath {
				t.Errorf("removeProcPrefix() = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}
