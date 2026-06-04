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

package reporter

import (
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// fakeReporter satisfies ParcaReporter; it captures every LogEvent batch sent
// through ReportLogEvents and ignores ReportTraceEvent. Tests inspect captured.
type fakeReporter struct {
	captured []LogEvent
}

func (f *fakeReporter) ReportTraceEvent(_ *libpf.Trace, _ *samples.TraceEventMeta) error {
	return nil
}

func (f *fakeReporter) ReportLogEvents(events []LogEvent) error {
	f.captured = append(f.captured, events...)
	return nil
}

func TestOTLPLogrusHook_FiresWithSeverityAndAttributes(t *testing.T) {
	rep := &fakeReporter{}
	hook := NewOTLPLogrusHook(rep)

	ts := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	entry := &logrus.Entry{
		Time:    ts,
		Level:   logrus.WarnLevel,
		Message: "something happened",
		Data: logrus.Fields{
			"pid":    int(4321),
			"comm":   "myapp",
			"err":    errors.New("boom"),
			"unk":    3.14, // unsupported type → stringified
			"u64":    uint64(7),
		},
	}
	require.NoError(t, hook.Fire(entry))

	require.Len(t, rep.captured, 1)
	ev := rep.captured[0]
	require.Equal(t, ts.UnixNano(), ev.TimestampNs)
	require.Equal(t, "something happened", ev.Body)
	require.Equal(t, plog.SeverityNumberWarn, ev.Severity)
	require.Equal(t, "WARNING", ev.SeverityText)

	require.Equal(t, LogAttr{Str: "myapp"}, ev.Attributes["comm"])
	require.Equal(t, LogAttr{Int: 4321, IsInt: true}, ev.Attributes["pid"])
	require.Equal(t, LogAttr{Str: "boom"}, ev.Attributes["err"])
	require.Equal(t, LogAttr{Str: "3.14"}, ev.Attributes["unk"])
	require.Equal(t, LogAttr{Int: 7, IsInt: true}, ev.Attributes["u64"])
}

func TestOTLPLogrusHook_SkipsSelfTaggedEntries(t *testing.T) {
	rep := &fakeReporter{}
	hook := NewOTLPLogrusHook(rep)

	entry := &logrus.Entry{
		Time:    time.Now(),
		Level:   logrus.WarnLevel,
		Message: "streamer error — must not loop",
		Data:    logrus.Fields{otlpSkipField: true, "extra": "x"},
	}
	require.NoError(t, hook.Fire(entry))
	require.Empty(t, rep.captured, "entries tagged otlp_skip=true must be dropped")
}

func TestOTLPLogrusHook_LevelMapping(t *testing.T) {
	cases := []struct {
		level logrus.Level
		want  plog.SeverityNumber
	}{
		{logrus.TraceLevel, plog.SeverityNumberTrace},
		{logrus.DebugLevel, plog.SeverityNumberDebug},
		{logrus.InfoLevel, plog.SeverityNumberInfo},
		{logrus.WarnLevel, plog.SeverityNumberWarn},
		{logrus.ErrorLevel, plog.SeverityNumberError},
		{logrus.FatalLevel, plog.SeverityNumberFatal},
		{logrus.PanicLevel, plog.SeverityNumberFatal},
	}
	for _, c := range cases {
		require.Equal(t, c.want, logrusLevelToSeverity(c.level), "level=%s", c.level)
	}
}

func TestOTLPLogrusHook_LevelsCoversAll(t *testing.T) {
	hook := NewOTLPLogrusHook(&fakeReporter{})
	require.ElementsMatch(t, logrus.AllLevels, hook.Levels())
}
