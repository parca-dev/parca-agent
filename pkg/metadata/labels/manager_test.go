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

package labels_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	promlabels "github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
)

func TestManager(t *testing.T) {
	t.Parallel()

	lm := labels.NewManager(
		log.NewNopLogger(),
		noop.NewTracerProvider().Tracer("test"),
		prometheus.NewRegistry(),
		[]metadata.Provider{
			metadata.Target("test", map[string]string{}),
		},
		[]*relabel.Config{
			// Add a node_pid label
			{
				SourceLabels: model.LabelNames{"node", "pid"},
				Separator:    ";",
				Regex:        relabel.MustNewRegexp(`(.*)`),
				Replacement:  "$1",
				TargetLabel:  "node_pid",
				Action:       relabel.Replace,
			},
			// Drop pid=2
			{
				SourceLabels: model.LabelNames{"pid"},
				Separator:    ";",
				Regex:        relabel.MustNewRegexp(`2`),
				Replacement:  "$1",
				Action:       relabel.Drop,
			},
		},
		false,
		time.Second,
	)

	ls, err := lm.LabelSet(context.TODO(), 1)
	require.NoError(t, err)

	// Should have the node_pid label
	require.Equal(t, model.LabelSet{
		"__name__": "fake_profiler",
		"node":     "test",
		"pid":      "1",
		"node_pid": "test;1",
	}, labels.WithProfilerName(ls, "fake_profiler"))

	lbs, err := lm.Labels(context.TODO(), 1)
	require.NoError(t, err)

	require.Equal(t,
		promlabels.New(promlabels.Labels{
			{Name: "__name__", Value: "fake_profiler"},
			{Name: "node", Value: "test"},
			{Name: "pid", Value: "1"},
			{Name: "node_pid", Value: "test;1"},
		}...),
		promlabels.New(append(lbs, labels.ProfilerName("fake_profiler"))...),
	)

	// Should be dropped
	ls, err = lm.LabelSet(context.TODO(), 2)
	require.NoError(t, err)
	require.Empty(t, ls)

	lbs, err = lm.Labels(context.TODO(), 2)
	require.NoError(t, err)
	require.Empty(t, lbs)
}
