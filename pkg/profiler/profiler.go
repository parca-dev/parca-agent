// Copyright 2022-2024 The Parca Authors
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

// TODO[btv]
// We should come up with a way to auto-generate
// matching C and Go structs from one description.
//
// typedef struct {
//     u32 pc_not_covered;
//     u32 no_unwind_info;
//     u32 missed_filter;
//     u32 mapping_not_found;
//     u32 chunk_not_found;
//     u32 null_unwind_table;
//     u32 table_not_found;
//     u32 rbp_failed;
//     u32 ra_failed;
//     u32 unsupported_fp_action;
//     u32 unsupported_cfa;
//     u32 truncated;
//     u32 previous_rsp_zero;
//     u32 previous_rip_zero;
//     u32 previous_rbp_zero;
//     u32 internal_error;
// } unwind_failed_reasons_t;

type UnwindFailedReasons struct {
	PcNotCovered        uint32
	NoUnwindInfo        uint32
	MissedFilter        uint32
	MappingNotFound     uint32
	ChunkNotFound       uint32
	NullUnwindTable     uint32
	TableNotFound       uint32
	RbpFailed           uint32
	RaFailed            uint32
	UnsupportedFpAction uint32
	UnsupportedCfa      uint32
	PreviousRspZero     uint32
	PreviousRipZero     uint32
	PreviousRbpZero     uint32
	InternalError       uint32
}

// TODO: Unify PID types.
type ProcessInfoManager interface {
	Fetch(ctx context.Context, pid int) (process.Info, error)
	FetchWithFreshMappings(ctx context.Context, pid int) (process.Info, error)
	Info(ctx context.Context, pid int) (process.Info, error)
}

type ProfileStore interface {
	Store(ctx context.Context, labels model.LabelSet, wrt profile.Writer, executableInfo []*profilestorepb.ExecutableInfo) error
}
