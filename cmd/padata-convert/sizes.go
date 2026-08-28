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
	"fmt"
	"path/filepath"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/klauspost/compress/zstd"
)

// zstdLevel matches what the offline-mode rotation loop uses, so the compressed
// numbers reflect what actually lands on disk.
var zstdEncoder, _ = zstd.NewWriter(nil)

func zstdSize(b []byte) int {
	return len(zstdEncoder.EncodeAll(b, nil))
}

type sizeRow struct {
	file    string
	samples int64
	// Arrow, as written by the agent today: uncompressed IPC.
	arrowRaw int
	// Arrow with the LZ4 the v2 gRPC path applies.
	arrowLZ4 int
	arrowZstd int
	// OTLP protobuf, and the same under zstd.
	otlpRaw  int
	otlpZstd int
	// Structural counts, to explain the size difference rather than just
	// report it.
	otlpProfiles  int
	otlpResources int
	otlpSamples   int
	locations     int
	functions     int
	strings       int
}

func runSizes(files []string, mem memory.Allocator, maxBatches int) {
	fmt.Printf("%-34s %9s %11s %11s %11s %11s %11s %8s %8s\n",
		"FILE", "SAMPLES", "ARROW", "ARROW+LZ4", "ARROW+ZST", "OTLP", "OTLP+ZST", "RAW", "ZST")

	var tot sizeRow
	for _, path := range files {
		row, err := measureFile(path, mem, maxBatches)
		if err != nil {
			fmt.Printf("%-34s ERROR: %v\n", filepath.Base(path), err)
			continue
		}

		fmt.Printf("%-34s %9d %11d %11d %11d %11d %11d %7.2fx %7.2fx\n",
			filepath.Base(path), row.samples,
			row.arrowRaw, row.arrowLZ4, row.arrowZstd, row.otlpRaw, row.otlpZstd,
			ratio(row.arrowRaw, row.otlpRaw), ratio(row.arrowZstd, row.otlpZstd))

		tot.samples += row.samples
		tot.arrowRaw += row.arrowRaw
		tot.arrowLZ4 += row.arrowLZ4
		tot.arrowZstd += row.arrowZstd
		tot.otlpRaw += row.otlpRaw
		tot.otlpZstd += row.otlpZstd
		tot.otlpProfiles += row.otlpProfiles
		tot.otlpResources += row.otlpResources
		tot.otlpSamples += row.otlpSamples
		tot.locations += row.locations
		tot.functions += row.functions
		tot.strings += row.strings
	}

	fmt.Printf("\n%-34s %9d %11d %11d %11d %11d %11d %7.2fx %7.2fx\n",
		"TOTAL", tot.samples,
		tot.arrowRaw, tot.arrowLZ4, tot.arrowZstd, tot.otlpRaw, tot.otlpZstd,
		ratio(tot.arrowRaw, tot.otlpRaw), ratio(tot.arrowZstd, tot.otlpZstd))

	fmt.Printf("\nBytes per sample:  arrow %.1f   arrow+zstd %.1f   otlp %.1f   otlp+zstd %.1f\n",
		perSample(tot.arrowRaw, tot.samples), perSample(tot.arrowZstd, tot.samples),
		perSample(tot.otlpRaw, tot.samples), perSample(tot.otlpZstd, tot.samples))
	fmt.Printf("Compression ratio: arrow %.2fx   otlp %.2fx\n",
		ratio(tot.arrowZstd, tot.arrowRaw), ratio(tot.otlpZstd, tot.otlpRaw))
	fmt.Printf("\nOTLP structure: %d resources, %d profiles, %d samples (from %d arrow rows, %.2fx fold)\n",
		tot.otlpResources, tot.otlpProfiles, tot.otlpSamples, tot.samples,
		ratio(tot.otlpSamples, int(tot.samples)))
	fmt.Printf("OTLP dictionary: %d locations, %d functions, %d strings\n",
		tot.locations, tot.functions, tot.strings)
}

// ratio reports how many times larger a is than b.
func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func perSample(bytes int, samples int64) float64 {
	if samples == 0 {
		return 0
	}
	return float64(bytes) / float64(samples)
}

func measureFile(path string, mem memory.Allocator, maxBatches int) (sizeRow, error) {
	row := sizeRow{file: path}

	p, err := readPadata(path, mem, maxBatches)
	if err != nil {
		return row, err
	}
	defer p.Release()

	if p.SchemaVersion != "v2" {
		return row, fmt.Errorf("only v2 is supported, got %s", p.SchemaVersion)
	}

	for _, rec := range p.Batches {
		row.samples += rec.NumRows()

		// Arrow side: re-serialize rather than reuse the on-disk size, so
		// all three arrow numbers come from the same record and are
		// comparable to each other.
		raw, err := writeIPC(rec, mem, false)
		if err != nil {
			return row, fmt.Errorf("write ipc: %w", err)
		}
		lz4, err := writeIPC(rec, mem, true)
		if err != nil {
			return row, fmt.Errorf("write ipc lz4: %w", err)
		}
		row.arrowRaw += len(raw)
		row.arrowLZ4 += len(lz4)
		row.arrowZstd += zstdSize(raw)

		// OTLP side: decode to canonical, re-encode, measure.
		samples, err := decodeArrowV2(rec)
		if err != nil {
			return row, fmt.Errorf("decode arrow: %w", err)
		}
		profiles, err := encodeOTLP(samples)
		if err != nil {
			return row, fmt.Errorf("encode otlp: %w", err)
		}
		pb, err := marshalOTLP(profiles)
		if err != nil {
			return row, fmt.Errorf("marshal otlp: %w", err)
		}
		row.otlpRaw += len(pb)
		row.otlpZstd += zstdSize(pb)

		row.otlpResources += profiles.ResourceProfiles().Len()
		dict := profiles.Dictionary()
		row.locations += dict.LocationTable().Len()
		row.functions += dict.FunctionTable().Len()
		row.strings += dict.StringTable().Len()
		for i := range profiles.ResourceProfiles().Len() {
			rp := profiles.ResourceProfiles().At(i)
			for j := range rp.ScopeProfiles().Len() {
				sp := rp.ScopeProfiles().At(j)
				row.otlpProfiles += sp.Profiles().Len()
				for k := range sp.Profiles().Len() {
					row.otlpSamples += sp.Profiles().At(k).Samples().Len()
				}
			}
		}
	}

	return row, nil
}
