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

import "time"

// maxSampleClockDrift is how far the device clock may run ahead of the wall
// clock between two reads before SampleCursor treats it as having jumped. It
// covers the lag of the newest sample behind the read.
const maxSampleClockDrift = 2 * time.Second

// SampleCursor picks the new samples out of what a device's sample buffer
// returns, and converts their timestamps, in microseconds on the device's
// clock, to wall-clock time.
//
// The device's clock can't be trusted to be continuous. On GB10 (DGX Spark)
// it re-bases each time the GPU wakes: forwards or backwards, by up to hours.
// A cursor kept only in device time then either stalls, ahead of every new
// sample, or re-reports the whole buffer. So SampleCursor also checks the
// device clock against the wall clock, and when they disagree it selects the
// new samples by wall time instead.
//
// Query NVML for the whole buffer (lastSeen 0), not for samples after the
// cursor: after a backwards jump NVML's own filter would return nothing.
type SampleCursor struct {
	// last is the newest sample reported, in device microseconds; 0 before
	// the first. lastWall is the wall time, in nanoseconds, it was reported
	// at, and lastRead the wall time of the read that returned it.
	last     uint64
	lastWall int64
	lastRead time.Time
}

// Advance takes the timestamp of the newest sample a read at now returned,
// and returns a function that, for each sample's timestamp, reports whether
// the sample is new and its wall-clock time in nanoseconds. Advance moves the
// cursor past the read's samples. It assumes the newest sample was taken at
// about now, unless it is one already reported. newest 0 means the read
// returned nothing.
func (c *SampleCursor) Advance(now time.Time, newest uint64) func(ts uint64) (wallNanos int64, ok bool) {
	if newest == 0 {
		return func(uint64) (int64, bool) { return 0, false }
	}
	last, lastWall := c.last, c.lastWall
	if last != 0 && newest == last {
		// Nothing new; NVML may return its last sample again. The clock
		// keeps the mapping it had.
		offset := lastWall - int64(last)*1000
		return func(ts uint64) (int64, bool) {
			return int64(ts)*1000 + offset, false
		}
	}

	nowNanos := now.UnixNano()
	offset := nowNanos - int64(newest)*1000
	continuous := last != 0 && newest > last &&
		time.Duration(newest-last)*time.Microsecond <= now.Sub(c.lastRead)+maxSampleClockDrift
	c.last, c.lastWall, c.lastRead = newest, nowNanos, now

	return func(ts uint64) (int64, bool) {
		if ts == 0 {
			return 0, false
		}
		wall := int64(ts)*1000 + offset
		switch {
		case last == 0:
			return wall, true
		case continuous:
			return wall, ts > last
		default:
			// The device clock jumped: what was reported before isn't
			// comparable in device time any more, but is in wall time.
			return wall, wall > lastWall
		}
	}
}
