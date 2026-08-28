package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// countLabelColumns reports how many label columns a record carries. v2 nests
// them in a struct; v1 keeps them top-level with a "labels." prefix.
func countLabelColumns(rec arrow.Record) int {
	for _, f := range rec.Schema().Fields() {
		if f.Name == "labels" {
			if st, ok := f.Type.(*arrow.StructType); ok {
				return st.NumFields()
			}
			return 0
		}
	}
	n := 0
	for _, f := range rec.Schema().Fields() {
		if len(f.Name) > 7 && f.Name[:7] == "labels." {
			n++
		}
	}
	return n
}

// runDecodeSample dumps a few decoded samples so the decoder can be eyeballed
// against reality before anything is built on top of it.
func runDecodeSample(files []string, mem memory.Allocator, limit int) {
	p, err := readPadata(files[0], mem, 1)
	if err != nil {
		fatal(err)
	}
	defer p.Release()
	if len(p.Batches) == 0 {
		fatal(fmt.Errorf("no batches in %s", files[0]))
	}

	samples, err := decodeArrowV2(p.Batches[0])
	if err != nil {
		fatal(err)
	}

	fmt.Printf("%s: decoded %d samples from batch 0\n\n", filepath.Base(files[0]), len(samples))
	if limit > len(samples) {
		limit = len(samples)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for i := 0; i < limit; i++ {
		_ = enc.Encode(samples[i])
	}
}

