package main

import (
	"context"
	"sync"
	"time"

	"github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/prometheus/pkg/labels"
)

type Profiler interface {
	Labels() []*profilestorepb.Label
	LastProfileTakenAt() time.Time
	LastError() error
}

type TargetSource interface {
	SetSink(func(Record))
	ActiveProfilers() []Profiler
}

type TargetManager struct {
	sources   []TargetSource
	observers []*observer
	omtx      *sync.RWMutex
}

func NewTargetManager(sources []TargetSource) *TargetManager {
	m := &TargetManager{
		sources: sources,
		omtx:    &sync.RWMutex{},
	}

	for _, source := range sources {
		source.SetSink(m.ObserveProfile)
	}

	return m
}

func (m *TargetManager) ActiveProfilers() []Profiler {
	res := []Profiler{}

	for _, source := range m.sources {
		res = append(res, source.ActiveProfilers()...)
	}

	return res
}

type observer struct {
	f func(Record)
}

func (m *TargetManager) ObserveProfile(r Record) {
	m.omtx.RLock()
	defer m.omtx.RUnlock()

	for _, o := range m.observers {
		o.f(r)
	}
}

func (m *TargetManager) Observe(f func(Record)) *observer {
	m.omtx.Lock()
	defer m.omtx.Unlock()

	o := &observer{
		f: f,
	}
	m.observers = append(m.observers, o)
	return o
}

func (m *TargetManager) RemoveObserver(o *observer) {
	m.omtx.Lock()
	defer m.omtx.Unlock()

	found := false
	i := 0
	for ; i < len(m.observers); i++ {
		if m.observers[i] == o {
			found = true
			break
		}
	}
	if found {
		m.observers = append(m.observers[:i], m.observers[i+1:]...)
	}
}

func (m *TargetManager) NextMatchingProfile(ctx context.Context, matchers []*labels.Matcher) (*profile.Profile, error) {
	pCh := make(chan *profile.Profile)
	defer close(pCh)

	o := m.Observe(func(r Record) {
		profileLabels := map[string]string{}
		for _, label := range r.Labels {
			profileLabels[label.Name] = label.Value
		}

		for _, matcher := range matchers {
			labelValue := profileLabels[matcher.Name]
			if !matcher.Matches(labelValue) {
				return
			}
		}

		pCh <- r.Profile.Copy()
	})
	defer m.RemoveObserver(o)

	select {
	case p := <-pCh:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
