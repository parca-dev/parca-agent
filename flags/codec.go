// Copyright 2023-2024 The Parca Authors
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

// Based on:
// https://github.com/planetscale/vtprotobuf#mixing-protobuf-implementations-with-grpc
// https://github.com/vitessio/vitess/blob/main/go/vt/servenv/grpc_codec.go

package flags

import (
	"fmt"

	gogoproto "github.com/gogo/protobuf/proto"
	"google.golang.org/protobuf/proto"

	_ "google.golang.org/grpc/encoding/proto"
)

// Name is the name registered for the proto compressor.
const Name = "proto"

type vtprotoCodec struct{}

type vtprotoMessage interface {
	MarshalVT() ([]byte, error)
	UnmarshalVT(data []byte) error
}

// pdataProtoMarshaler is the marshalling shape implemented by proto types
// generated under go.opentelemetry.io/collector/pdata/internal (used by the
// plogotlp / pmetricotlp / ptraceotlp gRPC clients). They don't satisfy any
// of the proto.Message variants above — they expose pdata's own custom
// SizeProto/MarshalProto pair, which writes a pre-sized buffer in reverse.
type pdataProtoMarshaler interface {
	SizeProto() int
	MarshalProto([]byte) int
}

// pdataProtoUnmarshaler is the receive-side counterpart of
// pdataProtoMarshaler. Server-side handlers / streaming readers go through
// this path.
type pdataProtoUnmarshaler interface {
	UnmarshalProto(data []byte) error
}

func (vtprotoCodec) Marshal(v any) ([]byte, error) {
	switch v := v.(type) {
	case vtprotoMessage:
		return v.MarshalVT()
	case pdataProtoMarshaler:
		buf := make([]byte, v.SizeProto())
		_ = v.MarshalProto(buf)
		return buf, nil
	case proto.Message:
		return proto.Marshal(v)
	case gogoproto.Message:
		return gogoproto.Marshal(v)
	default:
		return nil, fmt.Errorf("failed to marshal, message is %T, must satisfy the vtprotoMessage interface or want proto.Message, gogoproto.Message, or pdata SizeProto/MarshalProto", v)
	}
}

func (vtprotoCodec) Unmarshal(data []byte, v any) error {
	switch v := v.(type) {
	case vtprotoMessage:
		return v.UnmarshalVT(data)
	case pdataProtoUnmarshaler:
		return v.UnmarshalProto(data)
	case proto.Message:
		return proto.Unmarshal(data, v)
	case gogoproto.Message:
		return gogoproto.Unmarshal(data, v)
	default:
		return fmt.Errorf("failed to unmarshal, message is %T, must satisfy the vtprotoMessage interface or want proto.Message, gogoproto.Message, or pdata UnmarshalProto", v)
	}
}

func (vtprotoCodec) Name() string {
	return Name
}
