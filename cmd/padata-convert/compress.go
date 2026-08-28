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

package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"time"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// runCompress compares the transport compressors an OTLP/gRPC export could
// actually negotiate, against the Arrow numbers for reference.
//
// The distinction that matters: Arrow's LZ4 is *intra-format* -- the IPC
// metadata declares per-buffer compression, so both ends need only Arrow. gRPC
// compression is negotiated per-connection by name, so a compressor has to be
// registered in the client AND supported by the receiver. grpc-go ships gzip
// and nothing else.
func runCompress(files []string, mem memory.Allocator, maxBatches int) {
	fmt.Printf("%-32s %10s %11s %11s %11s %11s %11s\n",
		"FILE", "SAMPLES", "OTLP", "+GZIP", "+ZSTD-FAST", "+ZSTD-DEF", "+LZ4")

	var totSamples int64
	var totRaw, totGzip1, totGzip, totGzip9, totZstdFast, totZstd, totLZ4 int
	var gzip1Dur, gzipDur, gzip9Dur, zstdFastDur, zstdDur, lz4Dur time.Duration

	for _, path := range files {
		p, err := readPadata(path, mem, maxBatches)
		if err != nil {
			fmt.Printf("%-32s ERROR: %v\n", filepath.Base(path), err)
			continue
		}

		var samples int64
		var raw, g1, gz, g9, zf, zs, l4 int
		for _, rec := range p.Batches {
			samples += rec.NumRows()

			canon, err := decodeArrowV2(rec)
			if err != nil {
				fatal(err)
			}
			profiles, err := encodeOTLP(canon)
			if err != nil {
				fatal(err)
			}
			pb, err := marshalOTLP(profiles)
			if err != nil {
				fatal(err)
			}

			raw += len(pb)

			t := time.Now()
			g1 += gzipSizeLevel(pb, gzip.BestSpeed)
			gzip1Dur += time.Since(t)

			t = time.Now()
			gz += gzipSizeLevel(pb, gzip.DefaultCompression)
			gzipDur += time.Since(t)

			t = time.Now()
			g9 += gzipSizeLevel(pb, gzip.BestCompression)
			gzip9Dur += time.Since(t)

			t = time.Now()
			zf += zstdFastSize(pb)
			zstdFastDur += time.Since(t)

			t = time.Now()
			zs += zstdSize(pb)
			zstdDur += time.Since(t)

			t = time.Now()
			l4 += lz4Size(pb)
			lz4Dur += time.Since(t)
		}
		p.Release()

		fmt.Printf("%-32s %10d %11d %11d %11d %11d %11d\n",
			filepath.Base(path), samples, raw, gz, zf, zs, l4)

		totSamples += samples
		totRaw += raw
		totGzip1 += g1
		totGzip += gz
		totGzip9 += g9
		totZstdFast += zf
		totZstd += zs
		totLZ4 += l4
	}

	fmt.Printf("\n%-32s %10d %11d %11d %11d %11d %11d\n",
		"TOTAL", totSamples, totRaw, totGzip, totZstdFast, totZstd, totLZ4)

	mb := float64(totRaw) / (1 << 20)
	fmt.Printf("\n%-12s %9s %9s %10s %12s\n", "CODEC", "RATIO", "B/SAMPLE", "TIME", "THROUGHPUT")
	report := func(name string, size int, d time.Duration) {
		mbps := 0.0
		if d > 0 {
			mbps = mb / d.Seconds()
		}
		fmt.Printf("%-12s %8.2fx %9.1f %10v %9.0f MB/s\n",
			name, ratio(totRaw, size), perSample(size, totSamples),
			d.Round(time.Millisecond), mbps)
	}
	report("none", totRaw, 0)
	report("lz4", totLZ4, lz4Dur)
	report("gzip-1", totGzip1, gzip1Dur)
	report("gzip-6", totGzip, gzipDur)
	report("gzip-9", totGzip9, gzip9Dur)
	report("zstd-fastest", totZstdFast, zstdFastDur)
	report("zstd-default", totZstd, zstdDur)
	fmt.Printf("\nInput: %.0f MB of OTLP protobuf over %d samples\n", mb, totSamples)
}

func gzipSizeLevel(b []byte, level int) int {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, level)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Len()
}

// zstdFastEncoder is zstd at its lowest level, which is the interesting
// candidate for an agent: the CPU it spends is the customer's.
var zstdFastEncoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))

func zstdFastSize(b []byte) int {
	return len(zstdFastEncoder.EncodeAll(b, nil))
}

func lz4Size(b []byte) int {
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Len()
}
