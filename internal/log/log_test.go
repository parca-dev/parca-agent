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

package log

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// recorder keeps the messages of the records it handles.
type recorder struct{ msgs *[]string }

func (recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r recorder) Handle(_ context.Context, rec slog.Record) error {
	*r.msgs = append(*r.msgs, rec.Message)
	return nil
}
func (r recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r recorder) WithGroup(string) slog.Handler      { return r }

// TestForOTLP checks that the export side honors the level and SkipOTLP while
// stderr still gets the local-only records, without the routing attribute.
func TestForOTLP(t *testing.T) {
	var stderr bytes.Buffer
	var exported []string
	Setup(&stderr, "logfmt", slog.LevelInfo)
	Tee(ForOTLP(recorder{&exported}))

	slog.Debug("below level")
	slog.Info("everywhere")
	slog.Info("local", SkipOTLP)
	slog.With(SkipOTLP).Warn("local via With")
	slog.With("k", "v").WithGroup("g").Warn("grouped")

	require.Equal(t, []string{"everywhere", "grouped"}, exported)
	require.Contains(t, stderr.String(), "msg=local\n")
	require.Contains(t, stderr.String(), `msg="local via With"`)
	require.NotContains(t, stderr.String(), SkipOTLPKey)
	require.NotContains(t, stderr.String(), "below level")
}
