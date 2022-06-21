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
	"context"
	"sync"

	"github.com/go-kit/log"
	"github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"google.golang.org/grpc"
)

type profileListener struct {
	next      profilestorepb.ProfileStoreServiceClient
	observers []*observer
	omtx      *sync.Mutex
	logger    log.Logger
}

func NewProfileListener(logger log.Logger, next profilestorepb.ProfileStoreServiceClient) *profileListener {
	return &profileListener{
		next:      next,
		observers: []*observer{},
		omtx:      &sync.Mutex{},
		logger:    logger,
	}
}

func (l *profileListener) WriteRaw(ctx context.Context, r *profilestorepb.WriteRawRequest, opts ...grpc.CallOption) (*profilestorepb.WriteRawResponse, error) {
	l.observeProfile(r)
	return l.next.WriteRaw(ctx, r, opts...)
}

type observer struct {
	f func(*profilestorepb.WriteRawRequest)
}

func (l *profileListener) observeProfile(r *profilestorepb.WriteRawRequest) {
	l.omtx.Lock()
	defer l.omtx.Unlock()

	for _, o := range l.observers {
		o.f(r)
	}
}

func (l *profileListener) observe(f func(*profilestorepb.WriteRawRequest)) *observer {
	l.omtx.Lock()
	defer l.omtx.Unlock()

	o := &observer{
		f: f,
	}
	l.observers = append(l.observers, o)
	return o
}

func (l *profileListener) removeObserver(o *observer) {
	l.omtx.Lock()
	defer l.omtx.Unlock()

	found := false
	i := 0
	for ; i < len(l.observers); i++ {
		if l.observers[i] == o {
			found = true
			break
		}
	}
	if found {
		l.observers = append(l.observers[:i], l.observers[i+1:]...)
	}
}

func (l *profileListener) NextMatchingProfile(ctx context.Context, matchers []*labels.Matcher) (*profile.Profile, error) {
	pCh := make(chan []byte)
	defer close(pCh)

	o := l.observe(func(r *profilestorepb.WriteRawRequest) {
		var searchedSeries *profilestorepb.RawProfileSeries

	seriesloop:
		for _, series := range r.Series {
			profileLabels := model.LabelSet{}

			for _, label := range series.Labels.Labels {
				profileLabels[model.LabelName(label.Name)] = model.LabelValue(label.Value)
			}

			for _, matcher := range matchers {
				labelValue := profileLabels[model.LabelName(matcher.Name)]
				if !matcher.Matches(string(labelValue)) {
					continue seriesloop
				}
			}
			searchedSeries = series
			break
		}

		if searchedSeries != nil {
			pCh <- searchedSeries.Samples[len(searchedSeries.Samples)-1].RawProfile
		}
	})
	defer l.removeObserver(o)

	select {
	case p := <-pCh:
		return profile.ParseData(p)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
