// Copyright (c) 2022 The Parca Authors
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
//

package profiler

import (
	"context"
	"time"

	"github.com/go-kit/log"

	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/target"
)

// This profiler does nothing. It serves as a skeleton of what other will have
// to be implemented when adding a new profiler.
type NoopProfiler struct{}

func NewNoopProfiler(
	logger log.Logger,
	reg prometheus.Registerer,
	ksymCache *ksym.Cache,
	objCache objectfile.Cache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	target model.LabelSet,
	profilingDuration time.Duration,
	allGroups func() map[string][]*target.Group,

) Profiler {
	return &NoopProfiler{}
}

func (p *NoopProfiler) Name() string {
	return "noop-profiler"
}

func (p *NoopProfiler) LastSuccessfulProfileStartedAt() time.Time {
	return time.Now()
}

func (p *NoopProfiler) NextProfileStartedAt() time.Time {
	return time.Now()
}

func (p *NoopProfiler) Stop() {
}

func (p *NoopProfiler) Run(ctx context.Context) error {
	return nil
}

func (p *NoopProfiler) Labels() model.LabelSet {
	return model.LabelSet{}
}

func (p *NoopProfiler) LastProfileTakenAt() time.Time {
	return time.Now()
}

func (p *NoopProfiler) LastError() error {
	return nil
}
