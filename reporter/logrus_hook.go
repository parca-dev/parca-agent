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
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/plog"
)

// otlpSkipField is a logrus entry field name. When present and true on an
// entry, OTLPLogrusHook drops the entry instead of forwarding it through
// ReportLogEvents. The log streamer tags its own error/partial-success warns
// with this field to break the feedback loop that would otherwise grow the
// streamer's queue every time an export fails.
const otlpSkipField = "otlp_skip"

// OTLPLogrusHook is a logrus.Hook that ships every captured entry through the
// supplied ParcaReporter as an OTLP log record. Install with
// logrus.AddHook(reporter.NewOTLPLogrusHook(rep)) after the reporter is
// constructed; entries logged before installation are not captured.
//
// Fire is non-blocking on the steady state: ReportLogEvents performs a single
// non-blocking channel send into the streamer's queue. Entries are silently
// dropped if the queue is saturated (accounted in the streamer's queueDrops
// counter); Fire never returns a non-nil error so it cannot interfere with
// the logrus call site.
type OTLPLogrusHook struct {
	rep ParcaReporter
}

// NewOTLPLogrusHook returns a hook bound to rep. The hook fires on every
// logrus level by default; logrus's own level filter is what actually
// gates which entries reach Fire.
func NewOTLPLogrusHook(rep ParcaReporter) *OTLPLogrusHook {
	return &OTLPLogrusHook{rep: rep}
}

// Levels returns logrus.AllLevels so the hook fires for every level the
// underlying logger emits. Filtering by level should be done by configuring
// the logger itself (e.g. --log-level).
func (h *OTLPLogrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire converts the logrus entry to a LogEvent and enqueues it via the
// reporter. Entries carrying the otlp_skip=true field are dropped to break
// the streamer→logrus→streamer feedback loop.
func (h *OTLPLogrusHook) Fire(e *logrus.Entry) error {
	if v, ok := e.Data[otlpSkipField]; ok {
		if b, ok := v.(bool); ok && b {
			return nil
		}
	}

	// Always emit at least `level` as a per-record attribute.
	attrs := make(map[string]LogAttr, len(e.Data)+1)
	attrs["level"] = LogAttr{Str: strings.ToUpper(e.Level.String())}
	for k, v := range e.Data {
		if k == otlpSkipField {
			continue
		}
		attrs[k] = toLogAttr(v)
	}

	ev := LogEvent{
		TimestampNs:         e.Time.UnixNano(),
		ObservedTimestampNs: time.Now().UnixNano(),
		Body:                e.Message,
		Severity:            logrusLevelToSeverity(e.Level),
		SeverityText:        strings.ToUpper(e.Level.String()),
		Attributes:          attrs,
	}

	// ReportLogEvents itself never returns an error in the current
	// implementation; even if it did we'd swallow it here to avoid
	// propagating into the logrus call site.
	_ = h.rep.ReportLogEvents([]LogEvent{ev})
	return nil
}

// toLogAttr maps a logrus field value to the tagged LogAttr union. Integer
// types are preserved; everything else is stringified via fmt.Sprint so we
// don't lose information for types that the OTLP attribute set could in
// principle represent (floats, bools, errors, structs) but our minimal
// LogAttr does not yet model.
func toLogAttr(v any) LogAttr {
	switch x := v.(type) {
	case string:
		return LogAttr{Str: x}
	case int:
		return LogAttr{Int: int64(x), IsInt: true}
	case int32:
		return LogAttr{Int: int64(x), IsInt: true}
	case int64:
		return LogAttr{Int: x, IsInt: true}
	case uint:
		return LogAttr{Int: int64(x), IsInt: true}
	case uint32:
		return LogAttr{Int: int64(x), IsInt: true}
	case uint64:
		return LogAttr{Int: int64(x), IsInt: true}
	case error:
		return LogAttr{Str: x.Error()}
	default:
		return LogAttr{Str: fmt.Sprint(v)}
	}
}

// logrusLevelToSeverity maps a logrus.Level to the closest OTLP severity
// number. Panic level shares Fatal since OTLP has no distinct panic bucket.
func logrusLevelToSeverity(l logrus.Level) plog.SeverityNumber {
	switch l {
	case logrus.TraceLevel:
		return plog.SeverityNumberTrace
	case logrus.DebugLevel:
		return plog.SeverityNumberDebug
	case logrus.InfoLevel:
		return plog.SeverityNumberInfo
	case logrus.WarnLevel:
		return plog.SeverityNumberWarn
	case logrus.ErrorLevel:
		return plog.SeverityNumberError
	case logrus.FatalLevel, logrus.PanicLevel:
		return plog.SeverityNumberFatal
	default:
		return plog.SeverityNumberUnspecified
	}
}
