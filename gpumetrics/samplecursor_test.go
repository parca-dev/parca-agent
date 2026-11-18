// Copyright 2026 The Parca Authors
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

package gpumetrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// buffer returns the timestamps, in device microseconds, of a sample buffer
// holding one sample every 200 ms over the span ending at newest.
func buffer(newest uint64, span time.Duration) []uint64 {
	const period = 200_000
	var ts []uint64
	for t := newest - uint64(span/time.Microsecond); t <= newest; t += period {
		ts = append(ts, t)
	}
	return ts
}

// read advances c with a read at now that returned samples, and returns the
// wall times of the samples it reports as new.
func read(c *SampleCursor, now time.Time, samples []uint64) []time.Time {
	var newest uint64
	for _, ts := range samples {
		newest = max(newest, ts)
	}
	fresh := c.Advance(now, newest)
	var out []time.Time
	for _, ts := range samples {
		if wall, ok := fresh(ts); ok {
			out = append(out, time.Unix(0, wall))
		}
	}
	return out
}

func TestSampleCursor(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	const device = uint64(3_732_090_000_000) // ~43 days, in µs
	sec := uint64(time.Second / time.Microsecond)

	t.Run("continuous clock", func(t *testing.T) {
		var c SampleCursor
		got := read(&c, start, buffer(device, 2*time.Second))
		require.Len(t, got, 11, "first read reports the whole buffer")
		require.Equal(t, start, got[10], "newest sample maps to the read time")
		require.Equal(t, start.Add(-2*time.Second), got[0])

		// 1 s later the buffer has 5 more samples.
		got = read(&c, start.Add(time.Second), buffer(device+sec, 2*time.Second))
		require.Len(t, got, 5)
		require.Equal(t, start.Add(200*time.Millisecond), got[0])
		require.Equal(t, start.Add(time.Second), got[4])
	})

	t.Run("repeated sample is not reported again", func(t *testing.T) {
		var c SampleCursor
		require.Len(t, read(&c, start, []uint64{device}), 1)
		// NVML keeps returning the same sample, e.g. for a process that
		// stopped using the GPU, long after it was taken.
		for i := 1; i <= 10; i++ {
			require.Empty(t, read(&c, start.Add(time.Duration(i)*time.Second), []uint64{device}))
		}
		// A new sample, 11 s of device time later, is reported at its time.
		got := read(&c, start.Add(11*time.Second), []uint64{device, device + 11*sec})
		require.Equal(t, []time.Time{start.Add(11 * time.Second)}, got)
	})

	t.Run("clock jumps forward", func(t *testing.T) {
		var c SampleCursor
		read(&c, start, buffer(device, 14*time.Second))
		// 5 s later the device clock reads 5 h ahead; the buffer covers
		// 14 s, of which only the last 5 s are new.
		jumped := device + 5*3600*sec
		got := read(&c, start.Add(5*time.Second), buffer(jumped, 14*time.Second))
		require.Len(t, got, 25)
		require.Equal(t, start.Add(200*time.Millisecond), got[0])
		require.Equal(t, start.Add(5*time.Second), got[24])

		// It continues from the new clock.
		got = read(&c, start.Add(6*time.Second), buffer(jumped+sec, 14*time.Second))
		require.Len(t, got, 5)
	})

	t.Run("clock jumps backward", func(t *testing.T) {
		var c SampleCursor
		read(&c, start, buffer(device, 14*time.Second))
		// The device clock reads 22 h behind: every sample is older than
		// the cursor in device time, which would stall a device-time cursor.
		behind := device - 22*3600*sec
		got := read(&c, start.Add(3*time.Second), buffer(behind, 14*time.Second))
		require.Len(t, got, 15)
		require.Equal(t, start.Add(200*time.Millisecond), got[0])
		require.Equal(t, start.Add(3*time.Second), got[14])

		got = read(&c, start.Add(4*time.Second), buffer(behind+sec, 14*time.Second))
		require.Len(t, got, 5)
		require.Equal(t, start.Add(4*time.Second), got[4])
	})

	t.Run("empty read", func(t *testing.T) {
		var c SampleCursor
		require.Empty(t, read(&c, start, nil))
		require.Len(t, read(&c, start.Add(time.Second), []uint64{device}), 1)
	})
}
