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
	"os"
	"path/filepath"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
)

// runRoundtrip proves the conversion is information-preserving by rendering
// both sides to canonical JSON and diffing.
//
// The path exercised is arrow -> canonical -> OTLP -> protobuf -> OTLP ->
// canonical, so it covers the wire encoding too rather than just the in-memory
// conversion. Any field the OTLP model cannot hold shows up here as a diff.
func runRoundtrip(files []string, mem memory.Allocator, maxBatches int, outDir string) {
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			fatal(err)
		}
	}

	var totalSamples, totalMismatched, totalBatches int
	allPass := true

	for _, path := range files {
		p, err := readPadata(path, mem, maxBatches)
		if err != nil {
			fmt.Printf("%-34s ERROR: %v\n", filepath.Base(path), err)
			allPass = false
			continue
		}

		for bi, rec := range p.Batches {
			totalBatches++

			before, err := decodeArrowV2(rec)
			if err != nil {
				fmt.Printf("%-34s batch %d decode: %v\n", filepath.Base(path), bi, err)
				allPass = false
				continue
			}

			// arrow -> canonical -> OTLP -> protobuf -> OTLP -> canonical
			after, err := throughOTLP(before)
			if err != nil {
				fmt.Printf("%-34s batch %d otlp: %v\n", filepath.Base(path), bi, err)
				allPass = false
				continue
			}

			// ... and back into arrow, then decoded again, so the loop is
			// closed through both wire formats rather than just one.
			back, err := throughArrow(after, mem)
			if err != nil {
				fmt.Printf("%-34s batch %d arrow re-encode: %v\n", filepath.Base(path), bi, err)
				allPass = false
				continue
			}

			beforeJSON, err := canonicalJSON(before)
			if err != nil {
				fatal(err)
			}
			afterJSON, err := canonicalJSON(after)
			if err != nil {
				fatal(err)
			}

			backJSON, err := canonicalJSON(back)
			if err != nil {
				fatal(err)
			}

			totalSamples += len(before)
			ok := bytes.Equal(beforeJSON, afterJSON) && bytes.Equal(beforeJSON, backJSON)
			if !ok {
				allPass = false
				n := diffCount(before, after)
				totalMismatched += n
				stage := "otlp"
				if bytes.Equal(beforeJSON, afterJSON) {
					stage = "arrow re-encode"
					n = diffCount(before, back)
				}
				fmt.Printf("%-34s batch %d MISMATCH at %s: %d in, %d out, %d differing\n",
					filepath.Base(path), bi, stage, len(before), len(after), n)
				if ob, oa, hasDiff := firstDiff(before, back); hasDiff {
					fmt.Printf("  only before: %s\n  only after:  %s\n", truncate(ob), truncate(oa))
				}

				if outDir != "" {
					base := fmt.Sprintf("%s-b%d", filepath.Base(path), bi)
					writeFile(filepath.Join(outDir, base+".arrow.json"), beforeJSON)
					writeFile(filepath.Join(outDir, base+".otlp.json"), afterJSON)
					writeFile(filepath.Join(outDir, base+".arrow2.json"), backJSON)
					fmt.Printf("  wrote %s.{arrow,otlp}.json\n", base)
				}
			} else if outDir != "" && bi == 0 {
				base := fmt.Sprintf("%s-b%d", filepath.Base(path), bi)
				writeFile(filepath.Join(outDir, base+".canonical.json"), beforeJSON)
			}
		}
		p.Release()
	}

	fmt.Printf("\n%d batches, %d samples\n", totalBatches, totalSamples)
	if allPass {
		fmt.Println("RESULT: lossless -- canonical JSON identical in both directions")
		return
	}
	fmt.Printf("RESULT: LOSSY -- %d samples differ\n", totalMismatched)
	os.Exit(1)
}

// throughOTLP runs canonical samples out to OTLP protobuf and back, so the
// check covers serialization rather than stopping at the in-memory model.
func throughOTLP(samples []canonSample) ([]canonSample, error) {
	profiles, err := encodeOTLP(samples)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	pb, err := marshalOTLP(profiles)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req := pprofileotlp.NewExportRequest()
	if err := req.UnmarshalProto(pb); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return decodeOTLP(req.Profiles())
}

// diffCount reports how many canonical samples fail to pair up, as a multiset
// difference so ordering is irrelevant.
func diffCount(before, after []canonSample) int {
	counts := make(map[string]int, len(before))
	for _, s := range before {
		counts[s.canonKey()]++
	}
	for _, s := range after {
		counts[s.canonKey()]--
	}

	n := 0
	for _, c := range counts {
		if c > 0 {
			n += c
		} else if c < 0 {
			n += -c
		}
	}
	return n
}

// firstDiff returns one differing pair, for reporting what changed rather than
// only that something did.
func firstDiff(before, after []canonSample) (string, string, bool) {
	counts := make(map[string]int, len(before))
	for _, s := range before {
		counts[s.canonKey()]++
	}
	for _, s := range after {
		counts[s.canonKey()]--
	}

	var onlyBefore, onlyAfter string
	for k, c := range counts {
		if c > 0 && onlyBefore == "" {
			onlyBefore = k
		}
		if c < 0 && onlyAfter == "" {
			onlyAfter = k
		}
	}
	return onlyBefore, onlyAfter, onlyBefore != "" || onlyAfter != ""
}

func writeFile(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal(err)
	}
}

// throughArrow re-encodes canonical samples into a v2 arrow record and decodes
// them again, closing the loop through the format the agent writes on disk.
func throughArrow(samples []canonSample, mem memory.Allocator) ([]canonSample, error) {
	rec, err := encodeArrowV2(samples, mem)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	defer rec.Release()

	// Serialize and read back rather than decoding the in-memory record, so
	// the IPC layer is covered too.
	raw, err := writeIPC(rec, mem, false)
	if err != nil {
		return nil, fmt.Errorf("write ipc: %w", err)
	}

	rt, err := readFramedBatchRaw(raw, mem)
	if err != nil {
		return nil, fmt.Errorf("read ipc: %w", err)
	}
	defer rt.Release()

	return decodeArrowV2(rt)
}

func truncate(s string) string {
	const max = 220
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

var _ = pprofile.NewProfiles
