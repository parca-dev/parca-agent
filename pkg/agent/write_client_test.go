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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/go-kit/log"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/stretchr/testify/require"
)

func isEqualSample(a, b []*profilestorepb.RawSample) bool {
	if len(a) != len(b) {
		return false
	}

	ret := true
	for i := range a {
		if !bytes.Equal(a[i].RawProfile, b[i].RawProfile) {
			ret = false
		}
	}
	return ret
}

func compareProfileSeries(a, b []*profilestorepb.RawProfileSeries) bool {
	if len(a) != len(b) {
		return false
	}

	ret := true
	for i := range a {
		if !isEqualLabel(a[i].Labels, b[i].Labels) || !isEqualSample(a[i].Samples, b[i].Samples) {
			ret = false
		}
	}
	return ret
}

func TestWriteClient(t *testing.T) {
	wc := NewNoopProfileStoreClient()
	batcher := NewBatchWriteClient(log.NewNopLogger(), wc, time.Second)

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

	ctx := context.Background()

	samples1 := []*profilestorepb.RawSample{{RawProfile: []byte{11, 4, 96}}}
	samples2 := []*profilestorepb.RawSample{{RawProfile: []byte{15, 11, 95}}}

	t.Run("insertFirstProfile", func(t *testing.T) {
		_, err := batcher.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
			Series: []*profilestorepb.RawProfileSeries{{
				Labels:  &labelset1,
				Samples: samples1,
			}},
		})

		series := []*profilestorepb.RawProfileSeries{{
			Labels:  &labelset1,
			Samples: samples1,
		}}

		require.NoError(t, err)
		require.Equal(t, true, compareProfileSeries(batcher.series, series))
	})

	t.Run("insertSecondProfile", func(t *testing.T) {
		_, err := batcher.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
			Series: []*profilestorepb.RawProfileSeries{{
				Labels:  &labelset2,
				Samples: samples2,
			}},
		})

		series := []*profilestorepb.RawProfileSeries{
			{
				Labels:  &labelset1,
				Samples: samples1,
			},
			{
				Labels:  &labelset2,
				Samples: samples2,
			},
		}

		require.NoError(t, err)
		require.Equal(t, true, compareProfileSeries(batcher.series, series))
	})

	t.Run("appendProfile", func(t *testing.T) {
		_, err := batcher.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
			Series: []*profilestorepb.RawProfileSeries{{
				Labels:  &labelset1,
				Samples: samples2,
			}},
		})

		series := []*profilestorepb.RawProfileSeries{
			{
				Labels:  &labelset1,
				Samples: append(samples1, samples2...),
			},
			{
				Labels:  &labelset2,
				Samples: samples2,
			},
		}

		require.NoError(t, err)
		require.Equal(t, true, compareProfileSeries(batcher.series, series))
	})
}
