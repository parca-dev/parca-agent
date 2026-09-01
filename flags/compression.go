// Copyright 2026 The Parca Authors
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

package flags

import (
	"compress/gzip"
	"fmt"

	"google.golang.org/grpc"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
)

// Compression names accepted by --remote-store-compression.
const (
	CompressionNone = "none"
	CompressionGzip = "gzip"
)

// ConfigureCompression resolves the compression flag into a gRPC call option,
// and reports whether there is one to apply. This is transport compression,
// unrelated to the LZ4 inside an Arrow v2 payload.
//
// It must run before any dial: SetLevel mutates the registered compressor's
// writer pool, which grpc-go documents as initialization-time only.
func ConfigureCompression(name string) (grpc.CallOption, bool, error) {
	switch name {
	case CompressionNone, "":
		return nil, false, nil

	case CompressionGzip:
		// Level 1 rather than the level-6 default: nearly twice the throughput
		// for 6.6% of the ratio, and the CPU belongs to the node being profiled.
		if err := grpcgzip.SetLevel(gzip.BestSpeed); err != nil {
			return nil, false, fmt.Errorf("set gzip level: %w", err)
		}
		return grpc.UseCompressor(grpcgzip.Name), true, nil

	default:
		return nil, false, fmt.Errorf("unknown compression %q; valid values are none, gzip", name)
	}
}
