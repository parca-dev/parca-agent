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

// padata-convert is an experiment, not a shipped tool. It converts parca-agent
// offline-mode Arrow files into OTLP/profiles and back, to answer two
// questions: how the two encodings compare on size, and whether the conversion
// is lossless in both directions.
//
// Losslessness is checked by rendering both sides to a canonical JSON form and
// diffing: arrow -> otlp -> arrow must produce the same canonical document as
// the original.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apache/arrow-go/v18/arrow/memory"
)

func main() {
	var (
		corpus     = flag.String("corpus", "", "Directory of .padata/.padata.zst files.")
		maxBatches = flag.Int("max-batches", 0, "Cap sample batches decoded per file (0 = all).")
		maxFiles   = flag.Int("max-files", 0, "Cap files processed (0 = all).")
		mode       = flag.String("mode", "inspect", "inspect | sizes | roundtrip")
		outDir     = flag.String("out", "", "Directory to write canonical JSON to (roundtrip mode).")
	)
	flag.Parse()

	if *corpus == "" {
		fmt.Fprintln(os.Stderr, "-corpus is required")
		os.Exit(2)
	}

	files, err := filepath.Glob(filepath.Join(*corpus, "*.padata*"))
	if err != nil {
		fatal(err)
	}
	sort.Strings(files)
	if *maxFiles > 0 && len(files) > *maxFiles {
		files = files[:*maxFiles]
	}
	if len(files) == 0 {
		fatal(fmt.Errorf("no .padata files under %s", *corpus))
	}

	mem := memory.DefaultAllocator

	switch *mode {
	case "inspect":
		runInspect(files, mem, *maxBatches)
	case "sizes":
		runSizes(files, mem, *maxBatches)
	case "roundtrip":
		runRoundtrip(files, mem, *maxBatches, *outDir)
	case "compress":
		runCompress(files, mem, *maxBatches)
	case "decode":
		runDecodeSample(files, mem, 2)
	default:
		fatal(fmt.Errorf("unknown mode %q", *mode))
	}
}

func runInspect(files []string, mem memory.Allocator, maxBatches int) {
	fmt.Printf("%-42s %-8s %-8s %-9s %-10s %s\n",
		"FILE", "SCHEMA", "BATCHES", "SAMPLES", "IPC BYTES", "LABEL COLS")
	for _, path := range files {
		p, err := readPadata(path, mem, maxBatches)
		if err != nil {
			fmt.Printf("%-42s ERROR: %v\n", filepath.Base(path), err)
			continue
		}

		var samples int64
		labelCols := 0
		if len(p.Batches) > 0 {
			for _, b := range p.Batches {
				samples += b.NumRows()
			}
			labelCols = countLabelColumns(p.Batches[0])
		}

		fmt.Printf("%-42s %-8s %-8d %-9d %-10d %d\n",
			filepath.Base(path), p.SchemaVersion, len(p.Batches), samples, p.RawBytes, labelCols)
		p.Release()
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
