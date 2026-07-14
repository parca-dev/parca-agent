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
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/log"
)

// OTLPSkipField is a logrus entry field name. When present and true on an
// entry, OTLPLogrusHook drops the entry instead of forwarding it via
// Logger.Emit. Producers that log internally (e.g. the probes per-fire debug
// line) tag their entries with this field to avoid re-shipping high-volume
// debug output through the OTLP pipeline.
const OTLPSkipField = "otlp_skip"

// OTLPLogrusHook is a logrus.Hook that ships every captured entry as an OTel
// log record through the supplied Logger. Install with
// logrus.AddHook(reporter.NewOTLPLogrusHook(rep.Logger("parca-agent.agent")))
// after the reporter is constructed; entries logged before installation are
// not captured.
//
// Fire is non-blocking on the steady state: the OTel SDK BatchProcessor's
// OnEmit performs a ring-buffer enqueue. Entries are silently dropped if the
// queue is saturated (the SDK tracks drops internally); Fire never returns
// a non-nil error so it cannot interfere with the logrus call site.
type OTLPLogrusHook struct {
	logger log.Logger
}

// NewOTLPLogrusHook returns a hook bound to logger. The hook fires on every
// logrus level by default; logrus's own level filter is what actually gates
// which entries reach Fire.
func NewOTLPLogrusHook(logger log.Logger) *OTLPLogrusHook {
	return &OTLPLogrusHook{logger: logger}
}

// Levels returns logrus.AllLevels so the hook fires for every level the
// underlying logger emits. Filtering by level should be done by configuring
// the logger itself (e.g. --log-level).
func (h *OTLPLogrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire converts the logrus entry to an OTel log.Record and emits it via the
// bound Logger. Entries carrying the otlp_skip=true field are dropped (see
// OTLPSkipField).
func (h *OTLPLogrusHook) Fire(e *logrus.Entry) error {
	if v, ok := e.Data[OTLPSkipField]; ok {
		if b, ok := v.(bool); ok && b {
			return nil
		}
	}

	var rec log.Record
	rec.SetTimestamp(e.Time)
	rec.SetObservedTimestamp(time.Now())
	rec.SetBody(log.StringValue(e.Message))
	rec.SetSeverity(logrusLevelToSeverity(e.Level))
	rec.SetSeverityText(strings.ToUpper(e.Level.String()))

	// Always emit `level` as a per-record attribute. The OTLP server
	// (polarsignals) doesn't store SeverityText, so the only way to filter
	// by level downstream is via attributes.
	rec.AddAttributes(log.String("level", strings.ToUpper(e.Level.String())))
	for k, v := range e.Data {
		if k == OTLPSkipField {
			continue
		}
		rec.AddAttributes(toLogKV(k, v))
	}

	h.logger.Emit(context.Background(), rec)
	return nil
}

// toLogKV maps a logrus field value to an OTel log.KeyValue. Integer types
// are preserved as Int / Int64; everything else is stringified via fmt.Sprint
// so we don't lose information for types the OTel KeyValue API could in
// principle represent (we don't bother modelling floats/bools yet -- add as
// needed when a real producer needs them).
func toLogKV(k string, v any) log.KeyValue {
	switch x := v.(type) {
	case string:
		return log.String(k, x)
	case int:
		return log.Int(k, x)
	case int32:
		return log.Int64(k, int64(x))
	case int64:
		return log.Int64(k, x)
	case uint:
		return log.Int64(k, int64(x))
	case uint32:
		return log.Int64(k, int64(x))
	case uint64:
		return log.Int64(k, int64(x))
	case error:
		return log.String(k, x.Error())
	default:
		return log.String(k, fmt.Sprint(v))
	}
}

// logrusLevelToSeverity maps a logrus.Level to the closest OTel severity.
// Panic level shares Fatal since OTel has no distinct panic bucket.
func logrusLevelToSeverity(l logrus.Level) log.Severity {
	switch l {
	case logrus.TraceLevel:
		return log.SeverityTrace
	case logrus.DebugLevel:
		return log.SeverityDebug
	case logrus.InfoLevel:
		return log.SeverityInfo
	case logrus.WarnLevel:
		return log.SeverityWarn
	case logrus.ErrorLevel:
		return log.SeverityError
	case logrus.FatalLevel, logrus.PanicLevel:
		return log.SeverityFatal
	default:
		return log.SeverityUndefined
	}
}
