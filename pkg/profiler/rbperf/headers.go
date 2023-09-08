// Copyright 2023 The Parca Authors
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

// nolint: unused
package rbperf

type (
	s8  = int8
	u8  = uint8
	s16 = int16
	u16 = uint16
	s32 = int32
	u32 = uint32
	s64 = int64
	u64 = uint64
)

type ProcessData struct {
	RbFrameAddr u64
	RbVersion   u32
	Padding_    [4]byte
	StartTime   u64
}

type RubyVersionOffsets struct {
	MajorVersion        int32
	MinorVersion        int32
	PatchVersion        int32
	VMOffset            int32
	VMSizeOffset        int32
	ControlFrameSizeof  int32
	CfpOffset           int32
	LabelOffset         int32
	PathFlavour         int32
	LineInfoSizeOffset  int32
	LineInfoTableOffset int32
	LinenoOffset        int32
	MainThreadOffset    int32
	EcOffset            int32
}
