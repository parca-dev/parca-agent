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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

var noopCloser = func() error { return nil }

func TestReleaseOnce(t *testing.T) {
	r := NewReference(&objectFile{}, noopCloser)

	err := r.Release()
	require.NoError(t, err)

	err = r.Release()
	require.Equalf(t, ErrReferenceReleased, err, "expected ErrReleased, actual: %s", err)

	err = r.Release()
	require.Equalf(t, ErrReferenceReleased, err, "expected ErrReleased, actual: %s", err)
}

func TestValue(t *testing.T) {
	v := &objectFile{}
	r := NewReference(v, noopCloser)

	require.Equal(t, v, r.Value().objectFile)

	// Release the reference and ensure that the value is no longer accessible.
	require.NoError(t, r.Release())

	func() {
		defer func() {
			require.Equalf(t, ErrReferenceReleased, recover(), "expected panic with ErrReleased, actual: %v", recover())
		}()

		r.Value()
	}()
}

func TestClosedOnce(t *testing.T) {
	callCount := atomic.NewInt32(0)
	closer := func() error {
		callCount.Inc()
		return nil
	}

	root := NewReference(&objectFile{}, closer)

	references := make([]*ObjectFile, 25)
	for i := range references {
		references[i] = root.MustClone()
	}

	err := root.Release()
	require.NoErrorf(t, err, "unexpected error releasing root reference: %s", err)

	require.Equalf(t, int32(0), callCount.Load(), "expected closer to not be called, actual: %d", callCount.Load())

	var wg sync.WaitGroup
	wg.Add(25)
	for i := range references {
		go func(idx int) {
			defer wg.Done()
			err := references[idx].Release()
			require.NoErrorf(t, err, "unexpected error releasing reference #%d: %s", idx, err)
		}(i)
	}
	wg.Wait()

	require.Equalf(t, int32(1), callCount.Load(), "expected closer to be called 1 time, actual: %d", callCount.Load())
}
