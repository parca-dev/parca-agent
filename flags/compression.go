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
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
)

// Compression names accepted by --remote-store-compression.
const (
	CompressionNone = "none"
	CompressionZstd = "zstd"
	CompressionGzip = "gzip"
)

// zstdCompressorName is the wire name. It matches what the OpenTelemetry
// Collector negotiates, so a receiver that advertises zstd accepts ours.
const zstdCompressorName = "zstd"

// zstdCompressor implements gRPC's encoding.Compressor on top of
// klauspost/compress, which is already a direct dependency. Writing the ~40
// lines here avoids pulling in a third-party gRPC compression module for one
// codec.
//
// Level is SpeedFastest deliberately. The CPU spent compressing is the
// customer's, on a node that is being profiled, and measurements over 1.7M
// samples of real agent output put SpeedFastest ahead of gzip on both axes:
// 2.77x vs 2.71x compression, at 145 MB/s vs 64 MB/s. The extra 3.6% that
// default-level zstd buys costs a third of the throughput.
type zstdCompressor struct {
	encoders sync.Pool
	decoders sync.Pool
}

func newZstdCompressor() *zstdCompressor {
	c := &zstdCompressor{}
	c.encoders.New = func() any {
		w, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			return err
		}
		return w
	}
	c.decoders.New = func() any {
		r, err := zstd.NewReader(nil)
		if err != nil {
			return err
		}
		return r
	}
	return c
}

func (c *zstdCompressor) Name() string { return zstdCompressorName }

func (c *zstdCompressor) Compress(w io.Writer) (io.WriteCloser, error) {
	got := c.encoders.Get()
	enc, ok := got.(*zstd.Encoder)
	if !ok {
		return nil, fmt.Errorf("zstd encoder: %v", got)
	}
	enc.Reset(w)
	return &zstdWriteCloser{enc: enc, pool: &c.encoders}, nil
}

type zstdWriteCloser struct {
	enc  *zstd.Encoder
	pool *sync.Pool
}

func (z *zstdWriteCloser) Write(p []byte) (int, error) { return z.enc.Write(p) }

// Close flushes the frame and returns the encoder to the pool. It deliberately
// does not close the encoder: Reset makes it reusable, and a per-message
// allocation would undo the point of the pool.
func (z *zstdWriteCloser) Close() error {
	err := z.enc.Close()
	z.pool.Put(z.enc)
	return err
}

func (c *zstdCompressor) Decompress(r io.Reader) (io.Reader, error) {
	got := c.decoders.Get()
	dec, ok := got.(*zstd.Decoder)
	if !ok {
		return nil, fmt.Errorf("zstd decoder: %v", got)
	}
	if err := dec.Reset(r); err != nil {
		c.decoders.Put(dec)
		return nil, err
	}
	return dec.IOReadCloser(), nil
}

var registerZstdOnce sync.Once

// RegisterZstdCompressor installs the zstd gRPC compressor. Idempotent, and
// safe to call before any dial.
func RegisterZstdCompressor() {
	registerZstdOnce.Do(func() {
		encoding.RegisterCompressor(newZstdCompressor())
	})
}

// ConfigureCompression resolves the compression flag into a gRPC call option,
// and reports whether there is one to apply.
//
// It must run before any dial or RPC: gzip's level is set by mutating the
// registered compressor's writer pool, which grpc-go documents as
// initialization-time only and not thread-safe.
//
// gRPC compression is negotiated per connection by codec name, so it is
// unrelated to the LZ4 the Arrow v2 path uses -- that is declared inside the
// Arrow IPC metadata and needs no agreement with the transport. It also means
// only codecs the *receiver* installed will work. grpc-go ships gzip on both
// sides; zstd is registered here but a receiver may reject it.
func ConfigureCompression(name string) (grpc.CallOption, bool, error) {
	switch name {
	case CompressionNone, "":
		return nil, false, nil

	case CompressionGzip:
		// BestSpeed rather than the level-6 default. Measured over 1.7M
		// samples of real agent output, level 1 runs at 192 MB/s against level
		// 6's 108 MB/s and gives up 6.6% of the ratio (43.1 vs 40.2 bytes per
		// sample). Level 9 is a trap: 15 MB/s for 4% over level 6. The CPU is
		// spent on a node that is being profiled, so the trade goes to speed.
		if err := grpcgzip.SetLevel(gzip.BestSpeed); err != nil {
			return nil, false, fmt.Errorf("set gzip level: %w", err)
		}
		return grpc.UseCompressor(grpcgzip.Name), true, nil

	case CompressionZstd:
		RegisterZstdCompressor()
		return grpc.UseCompressor(zstdCompressorName), true, nil

	default:
		return nil, false, fmt.Errorf("unknown compression %q; valid values are none, gzip, zstd", name)
	}
}
