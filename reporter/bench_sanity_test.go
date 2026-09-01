// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBenchCorpusSanity is the guard on the benchmark's input. A decoder that
// silently produced empty stacks or a single PID would still benchmark
// something, just not the thing being claimed -- and the result would look
// good, because an empty batch is fast.
func TestBenchCorpusSanity(t *testing.T) {
	events := loadBenchCorpus(t, 20000)
	stats := statsFor(events)

	t.Logf("events=%d frames=%d frames/sample=%.1f pids=%d mappings=%d",
		stats.events, stats.frames,
		float64(stats.frames)/float64(stats.events), stats.pids, stats.mappings)

	require.Positive(t, stats.frames, "every sample decoded to an empty stack")
	require.Greater(t, float64(stats.frames)/float64(stats.events), 1.0,
		"mean stack depth below 1 means the ListView offsets were misread")
	require.Greater(t, stats.pids, 1, "a single PID means the label struct was misread")
	require.Greater(t, stats.mappings, 1, "a single mapping means the location dictionary was misread")

	var withComm int
	for _, e := range events {
		if e.meta.Comm.String() != "" {
			withComm++
		}
	}
	require.Greater(t, withComm, len(events)/2, "most samples should carry a comm")
}
