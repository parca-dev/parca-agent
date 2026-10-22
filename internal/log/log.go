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

// Package log is parca-agent's logging front end: printf-style helpers over
// the process-wide slog logger, the same shape as the profiler's own log
// package, plus the setup that points the profiler's logger at the same
// handlers. Structured call sites can use log/slog directly; both end up in
// the handlers installed here.
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	ebpflog "go.opentelemetry.io/ebpf-profiler/log"
)

// SkipOTLP marks a record as local-only: handlers wrapped with ForOTLP drop
// records that carry it, so high-volume debug output stays on stderr. Add it
// as an attribute, e.g. slog.Debug("probe fire", log.SkipOTLP, ...).
var SkipOTLP = slog.Bool(SkipOTLPKey, true)

// SkipOTLPKey is the attribute key behind SkipOTLP.
const SkipOTLPKey = "otlp_skip"

var (
	// level is shared by every handler Setup and Tee install, so --log-level
	// governs the agent, the profiler and the OTLP export alike.
	level = new(slog.LevelVar)

	mu         sync.Mutex
	stderr     slog.Handler
	beforeExit []func()
)

// Setup installs a handler writing to w in format ("logfmt" or "json") at
// lvl as the process-wide logger, for the agent and the profiler. Records
// logged through the standard library's log package land there too.
func Setup(w io.Writer, format string, lvl slog.Level) {
	level.Set(lvl)
	opts := &slog.HandlerOptions{
		Level: level,
		// SkipOTLP is routing, not content; keep it off the local output.
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == SkipOTLPKey {
				return slog.Attr{}
			}
			return a
		},
	}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	mu.Lock()
	defer mu.Unlock()
	stderr = h
	install(h)
}

// Tee additionally sends every record to h. Wrap an exporting handler with
// ForOTLP so the configured level and SkipOTLP apply to it.
func Tee(h slog.Handler) {
	mu.Lock()
	defer mu.Unlock()
	if stderr == nil {
		stderr = slog.Default().Handler()
	}
	install(slog.NewMultiHandler(stderr, h))
}

// ForOTLP wraps h, a handler that exports records off the host, so that it
// honors the configured level and drops records marked SkipOTLP.
func ForOTLP(h slog.Handler) slog.Handler { return otlpHandler{h: h} }

type otlpHandler struct {
	h    slog.Handler
	skip bool // WithAttrs was given SkipOTLP
}

func (o otlpHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return !o.skip && l >= level.Level() && o.h.Enabled(ctx, l)
}

func (o otlpHandler) Handle(ctx context.Context, r slog.Record) error {
	skip := false
	r.Attrs(func(a slog.Attr) bool {
		skip = isSkip(a)
		return !skip
	})
	if skip {
		return nil
	}
	return o.h.Handle(ctx, r)
}

func (o otlpHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for _, a := range attrs {
		if isSkip(a) {
			return otlpHandler{h: o.h, skip: true}
		}
	}
	return otlpHandler{h: o.h.WithAttrs(attrs), skip: o.skip}
}

func (o otlpHandler) WithGroup(name string) slog.Handler {
	return otlpHandler{h: o.h.WithGroup(name), skip: o.skip}
}

func isSkip(a slog.Attr) bool {
	return a.Key == SkipOTLPKey && a.Value.Kind() == slog.KindBool && a.Value.Bool()
}

func install(h slog.Handler) {
	l := slog.New(h)
	slog.SetDefault(l)
	ebpflog.SetLogger(*l)
}

// SetLevel changes the level of every installed handler.
func SetLevel(lvl slog.Level) { level.Set(lvl) }

// Enabled reports whether records at lvl are logged, so hot paths can skip
// building attributes for records that would be dropped.
func Enabled(lvl slog.Level) bool {
	return slog.Default().Enabled(context.Background(), lvl)
}

// BeforeExit registers f to run before Fatal exits the process, e.g. to
// flush records that have not been exported yet.
func BeforeExit(f func()) {
	mu.Lock()
	defer mu.Unlock()
	beforeExit = append(beforeExit, f)
}

func logf(lvl slog.Level, format string, args ...any) {
	l := slog.Default()
	if l.Enabled(context.Background(), lvl) {
		l.Log(context.Background(), lvl, fmt.Sprintf(format, args...))
	}
}

// Debugf logs a formatted message at debug level.
func Debugf(format string, args ...any) { logf(slog.LevelDebug, format, args...) }

// Infof logs a formatted message at info level.
func Infof(format string, args ...any) { logf(slog.LevelInfo, format, args...) }

// Warnf logs a formatted message at warn level.
func Warnf(format string, args ...any) { logf(slog.LevelWarn, format, args...) }

// Errorf logs a formatted message at error level.
func Errorf(format string, args ...any) { logf(slog.LevelError, format, args...) }

// Debug logs msg at debug level.
func Debug(msg string) { slog.Debug(msg) }

// Info logs msg at info level.
func Info(msg string) { slog.Info(msg) }

// Warn logs msg at warn level.
func Warn(msg string) { slog.Warn(msg) }

// Error logs msg at error level.
func Error(msg string) { slog.Error(msg) }

// Fatalf logs a formatted message at error level, runs the BeforeExit hooks
// and exits with status 1.
func Fatalf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	exit()
}

// Fatal logs msg at error level, runs the BeforeExit hooks and exits with
// status 1.
func Fatal(msg string) {
	slog.Error(msg)
	exit()
}

// exitTimeout bounds the BeforeExit hooks, so a stuck export cannot keep a
// failing agent alive.
const exitTimeout = 5 * time.Second

func exit() {
	mu.Lock()
	hooks := beforeExit
	mu.Unlock()
	done := make(chan struct{})
	go func() {
		for _, f := range hooks {
			f()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(exitTimeout):
	}
	os.Exit(1)
}
