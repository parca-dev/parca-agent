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

package processlabels

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"
)

// TestForkIsolatesCache checks a fork applies the same relabel rules but
// doesn't see results cached under the parent's seed.
func TestForkIsolatesCache(t *testing.T) {
	keepOOM := &relabel.Config{
		Action: relabel.Keep, SourceLabels: []model.LabelName{"job"},
		Regex: relabel.MustNewRegexp("oomprof"), Separator: ";",
	}
	parent, err := New(Config{CacheSize: 16, LabelTTL: time.Minute, NodeName: "n", RelabelConfigs: []*relabel.Config{keepOOM}})
	require.NoError(t, err)
	fork, err := parent.Fork()
	require.NoError(t, err)
	require.Equal(t, parent.RelabelConfigs(), fork.RelabelConfigs())

	res := parent.Resolve(context.Background(), 42, func(lb *labels.Builder) { lb.Set("job", "oomprof") })
	require.True(t, res.Keep)

	res = fork.Resolve(context.Background(), 42, nil)
	require.False(t, res.Keep, "the fork resolves pid 42 itself, without the parent's seed")
}
