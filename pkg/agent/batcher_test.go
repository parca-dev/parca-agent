// Copyright 2021 The Parca Authors
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

package agent

import (
	"testing"

	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestScheduler(t *testing.T) {
	wc := NewNoopProfileStoreClient()
	batcher := NewBatcher(wc)

	labelset1 := profilestorepb.LabelSet{
		Labels: []*profilestorepb.Label{{
			Name:  "n1",
			Value: "v1",
		}},
	}
	labelset2 := profilestorepb.LabelSet{
		Labels: []*profilestorepb.Label{{
			Name:  "n2",
			Value: "v2",
		}},
	}

	labelsetHash1 := Hash(labelset1)
	labelsetHash2 := Hash(labelset2)

	samples1 := []*profilestorepb.RawSample{{RawProfile: []byte{11, 04, 96}}}
	samples2 := []*profilestorepb.RawSample{{RawProfile: []byte{15, 11, 95}}}

	t.Run("insertFirstProfile", func(t *testing.T) {

		batcher.Scheduler(profilestorepb.RawProfileSeries{
			Labels:  &labelset1,
			Samples: samples1,
		})

		series := map[uint64]*profilestorepb.RawProfileSeries{
			labelsetHash1: &profilestorepb.RawProfileSeries{
				Labels:  &labelset1,
				Samples: samples1,
			},
		}

		require.Equal(t, series[labelsetHash1].Samples,
			batcher.series[labelsetHash1].Samples)
	})

	t.Run("insertSecondProfile", func(t *testing.T) {

		batcher.Scheduler(profilestorepb.RawProfileSeries{
			Labels:  &labelset2,
			Samples: samples2,
		})

		series := map[uint64]*profilestorepb.RawProfileSeries{
			labelsetHash1: &profilestorepb.RawProfileSeries{
				Labels:  &labelset1,
				Samples: samples1,
			},
			labelsetHash2: &profilestorepb.RawProfileSeries{
				Labels:  &labelset2,
				Samples: samples2,
			},
		}

		require.Equal(t, series[labelsetHash1].Samples,
			batcher.series[labelsetHash1].Samples)

		require.Equal(t, series[labelsetHash2].Samples,
			batcher.series[labelsetHash2].Samples)
	})

	t.Run("appendProfile", func(t *testing.T) {

		batcher.Scheduler(profilestorepb.RawProfileSeries{
			Labels:  &labelset1,
			Samples: samples2,
		})

		series := map[uint64]*profilestorepb.RawProfileSeries{
			labelsetHash1: &profilestorepb.RawProfileSeries{
				Labels:  &labelset1,
				Samples: append(samples1, samples2...),
			},
			labelsetHash2: &profilestorepb.RawProfileSeries{
				Labels:  &labelset2,
				Samples: samples2,
			},
		}

		require.Equal(t, series[labelsetHash1].Samples,
			batcher.series[labelsetHash1].Samples)

		require.Equal(t, series[labelsetHash2].Samples,
			batcher.series[labelsetHash2].Samples)

	})

	t.Run("hash", func(t *testing.T) {

		labelset := profilestorepb.LabelSet{
			Labels: []*profilestorepb.Label{{
				Name:  "n1",
				Value: "v1",
			}},
		}

		labelsetHash := Hash(labelset)

		require.Equal(t, uint64(0xa3b730de852c2e2c), labelsetHash)
	})

}
