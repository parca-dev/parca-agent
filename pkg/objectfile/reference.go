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

package objectfile

import (
	"errors"
	"runtime"
	"sync"

	"go.uber.org/atomic"
)

// This component provides a mechanism for managing the life cycle of a resource manually using reference counting.
// e.g. When a file is evicted from the memory, it ensures that the file isn't removed from disk until all active users have completed their operations.
//
// While similar functionality can be achieved using runtime.SetFinalizer (this component also use it as a fallback mechanism),
// this component takes a more explicit approach towards handling references, which not only provides greater clarity,
// but also gives ability to avoid the overhead of allocation/opening costly resources repeatedly.

// This component also provides full concurrent safety. All operations are wait-free, ensuring smooth execution even with multiple concurrent accesses.
// One of the key guarantees is that the closer/destructor, which handles the removal of references, is called only once, and that too only when no live references remain.
// This is executed synchronously upon the release of the final reference.

// Furthermore, it ensures that references can be released only once, preventing potential duplication errors.
// Importantly, no new references can be created once the closer/destructor has run its course, preserving the integrity of the process.
// Another feature is that if Clone function is called post the execution of Release function, the cloning process will fail.

var (
	ErrReferenceReleased     = errors.New("reference already released")
	ErrResourceAlreadyClosed = errors.New("resource already closed")
)

type resource struct {
	*objectFile

	refCount *atomic.Int32
	// This function intentionally excluded from the interface.
	// The value type should not expose the closer/destructor except through the reference.
	mtx    *sync.Mutex
	closed bool
	closer func() error
}

func newResource(val *objectFile, closer func() error) *resource {
	res := &resource{val, atomic.NewInt32(0), &sync.Mutex{}, false, closer}
	defer res.Inc()
	// See https://pkg.go.dev/runtime#SetFinalizer.
	runtime.SetFinalizer(res, func(res *resource) error {
		// This is a fail-safe mechanism to ensure that the closer is called,
		// even if the reference is not released manually.
		return res.closer()
	})
	return res
}

func (r *resource) Inc() int32 {
	return r.refCount.Inc()
}

func (r *resource) Dec() int32 {
	return r.refCount.Dec()
}

func (r *resource) Value() *objectFile {
	r.mtx.Lock()
	if r.closed {
		r.mtx.Unlock()
		panic(ErrResourceAlreadyClosed)
	}
	r.mtx.Unlock()

	return r.objectFile
}

func (r *resource) Close() error {
	if r.closer == nil {
		return nil
	}

	r.mtx.Lock()
	defer r.mtx.Unlock()

	if err := r.closer(); err != nil {
		return err
	}
	r.closed = true
	return nil
}

type ObjectFile struct {
	// The type should be a pointer type.
	*resource
	released *atomic.Bool
}

func NewReference(val *objectFile, closer func() error) *ObjectFile {
	return newReference(newResource(val, closer))
}

func newReference(res *resource) *ObjectFile {
	ref := &ObjectFile{res, atomic.NewBool(false)}
	// See https://pkg.go.dev/runtime#SetFinalizer.
	runtime.SetFinalizer(ref, func(ref *ObjectFile) error {
		// This is a fail-safe mechanism to ensure that the closer/destructor is called,
		// even if the reference is not released manually.
		ref.MustRelease()
		// return ref.Release()
		return nil
	})
	return ref
}

func (r *ObjectFile) Clone() (*ObjectFile, error) {
	if r.released.Load() {
		return nil, ErrReferenceReleased
	}
	r.resource.Inc()
	return newReference(r.resource), nil
}

func (r *ObjectFile) MustClone() *ObjectFile {
	ref, err := r.Clone()
	if err != nil {
		panic(err)
	}
	return ref
}

func (r *ObjectFile) Release() error {
	if !r.released.CompareAndSwap(false, true) {
		return ErrReferenceReleased
	}
	if r.resource.Dec() == 0 {
		return r.resource.Close()
	}
	return nil
}

func (r *ObjectFile) MustRelease() {
	if !r.released.CompareAndSwap(false, true) {
		panic(ErrReferenceReleased)
	}
	if r.resource.Dec() == 0 {
		if err := r.resource.Close(); err != nil {
			panic(err)
		}
	}
}

// Guard is a reference guard that to prevent actual reference to be released,
// until the operation is complete with underlying value.
type Guard struct {
	*objectFile
	ref *ObjectFile // Keeping a reference to the actual reference to prevent it from being GCed.
}

// Value intentionally panics to prevent accidental use of the value after the reference is released.
func (r *ObjectFile) Value() Guard {
	if r.released.Load() {
		panic(ErrReferenceReleased)
	}
	return Guard{r.objectFile, r}
}
