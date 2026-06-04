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
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// captureExporter is a sdklog.Exporter that stores every record passed to it.
// Used with a SimpleProcessor so emit calls land synchronously in `records`,
// making assertions immediately visible without ForceFlush gymnastics.
type captureExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *captureExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, records...)
	return nil
}
func (e *captureExporter) Shutdown(_ context.Context) error   { return nil }
func (e *captureExporter) ForceFlush(_ context.Context) error { return nil }

// newCaptureLogger builds a Logger whose emissions land in the returned
// exporter's `records` slice for the test to inspect.
func newCaptureLogger() (log.Logger, *captureExporter) {
	exp := &captureExporter{}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)
	return provider.Logger("test"), exp
}

// attrMap walks a record's attributes into a map for easy lookup in asserts.
func attrMap(r sdklog.Record) map[string]log.Value {
	m := map[string]log.Value{}
	r.WalkAttributes(func(kv log.KeyValue) bool {
		m[kv.Key] = kv.Value
		return true
	})
	return m
}

func TestOTLPLogrusHook_FiresWithSeverityAndAttributes(t *testing.T) {
	logger, exp := newCaptureLogger()
	hook := NewOTLPLogrusHook(logger)

	ts := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	entry := &logrus.Entry{
		Time:    ts,
		Level:   logrus.WarnLevel,
		Message: "something happened",
		Data: logrus.Fields{
			"pid":  int(4321),
			"comm": "myapp",
			"err":  errors.New("boom"),
			"unk":  3.14, // unsupported type → stringified
			"u64":  uint64(7),
		},
	}
	require.NoError(t, hook.Fire(entry))

	require.Len(t, exp.records, 1)
	rec := exp.records[0]
	require.Equal(t, ts, rec.Timestamp())
	require.Equal(t, "something happened", rec.Body().AsString())
	require.Equal(t, log.SeverityWarn, rec.Severity())
	require.Equal(t, "WARNING", rec.SeverityText())

	attrs := attrMap(rec)
	require.Equal(t, "myapp", attrs["comm"].AsString())
	require.EqualValues(t, 4321, attrs["pid"].AsInt64())
	require.Equal(t, "boom", attrs["err"].AsString())
	require.Equal(t, "3.14", attrs["unk"].AsString())
	require.EqualValues(t, 7, attrs["u64"].AsInt64())
	require.Equal(t, "WARNING", attrs["level"].AsString())
}

func TestOTLPLogrusHook_SkipsSelfTaggedEntries(t *testing.T) {
	logger, exp := newCaptureLogger()
	hook := NewOTLPLogrusHook(logger)

	entry := &logrus.Entry{
		Time:    time.Now(),
		Level:   logrus.WarnLevel,
		Message: "streamer error — must not loop",
		Data:    logrus.Fields{OTLPSkipField: true, "extra": "x"},
	}
	require.NoError(t, hook.Fire(entry))
	require.Empty(t, exp.records, "entries tagged otlp_skip=true must be dropped")
}

func TestOTLPLogrusHook_AlwaysEmitsLevelAttr(t *testing.T) {
	logger, exp := newCaptureLogger()
	hook := NewOTLPLogrusHook(logger)

	entry := &logrus.Entry{
		Time:    time.Now(),
		Level:   logrus.InfoLevel,
		Message: "bare",
	}
	require.NoError(t, hook.Fire(entry))
	require.Len(t, exp.records, 1)
	require.Equal(t, "INFO", attrMap(exp.records[0])["level"].AsString())
}

func TestOTLPLogrusHook_LevelMapping(t *testing.T) {
	cases := []struct {
		level logrus.Level
		want  log.Severity
	}{
		{logrus.TraceLevel, log.SeverityTrace},
		{logrus.DebugLevel, log.SeverityDebug},
		{logrus.InfoLevel, log.SeverityInfo},
		{logrus.WarnLevel, log.SeverityWarn},
		{logrus.ErrorLevel, log.SeverityError},
		{logrus.FatalLevel, log.SeverityFatal},
		{logrus.PanicLevel, log.SeverityFatal},
	}
	for _, c := range cases {
		require.Equal(t, c.want, logrusLevelToSeverity(c.level), "level=%s", c.level)
	}
}

func TestOTLPLogrusHook_LevelsCoversAll(t *testing.T) {
	logger, _ := newCaptureLogger()
	hook := NewOTLPLogrusHook(logger)
	require.ElementsMatch(t, logrus.AllLevels, hook.Levels())
}
