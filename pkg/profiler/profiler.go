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
//

package profiler

import (
	"context"

	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profile"
)

// PID is the process ID of the profiling target.
// See https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.3/html_node/libc_554.html
type PID int32

// StackID consists of two parts: the first part is the process ID of the profiling target,
// the second part is the thread ID of the stack trace has been collected from.
type StackID struct {
	PID PID
	TID PID
}

// TODO: Unify PID types.
type ProcessInfoManager interface {
	Fetch(ctx context.Context, pid int) (process.Info, error)
	Info(ctx context.Context, pid int) (process.Info, error)
}

type ProfileStore interface {
	Store(ctx context.Context, labels model.LabelSet, wrt profile.Writer, executableInfo []*profilestorepb.ExecutableInfo) error
}
