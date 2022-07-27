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
)

type Profiler interface {
	Name() string
	Run(ctx context.Context) error
	Stop()

	// todo re-evaluate these
	Labels() model.LabelSet
	LastSuccessfulProfileStartedAt() time.Time
	NextProfileStartedAt() time.Time
	LastError() error
}

type NewProfilerFunc func(
	logger log.Logger,
	reg prometheus.Registerer,
	ksymCache *ksym.Cache,
	objCache objectfile.Cache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	target model.LabelSet,
	progfilingDuration time.Duration,
	allGroups func() map[int]model.LabelSet,
) Profiler

type ProfilerType int64

const (
	ProfilerTypeNoop ProfilerType = iota
	ProfilerTypeCPU
)
