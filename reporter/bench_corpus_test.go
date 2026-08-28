// SPDX-License-Identifier: Apache-2.0

// Corpus loading for the encoder benchmarks: read an offline-mode .padata file
// and turn its rows back into the ReportTraceEvent arguments that produced
// them, once, outside the benchmark timer. Real data because encoder cost is
// driven by cardinality, which a generator gets wrong unless you already know
// the answer.
//
// FileIDs do not survive the round trip: the arrow schema keeps only
// (filename, build ID), so one is synthesized by hashing that pair. The
// encoders use it as a dictionary key and as the htlhash build-ID fallback,
// both of which need only stability, so cardinality is faithful and the values
// are not.
package reporter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/klauspost/compress/zstd"
	"go.opentelemetry.io/ebpf-profiler/libpf"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// benchCorpusEnv names the .padata or .padata.zst file to replay. The
// benchmarks skip without it, so `go test ./...` stays hermetic.
const benchCorpusEnv = "PARCA_BENCH_CORPUS"

const padataMagic uint32 = 0xA6E7CCCA

// traceEvent is one reconstructed ReportTraceEvent call.
type traceEvent struct {
	trace *libpf.Trace
	meta  *samples.TraceEventMeta
}

// loadBenchCorpus reads the corpus named by benchCorpusEnv, capped at maxRows
// (0 for all). It reports the file it read so a benchmark result can be tied
// back to its input.
func loadBenchCorpus(tb testing.TB, maxRows int) []traceEvent {
	tb.Helper()

	path := os.Getenv(benchCorpusEnv)
	if path == "" {
		tb.Skipf("set %s to a .padata[.zst] file to run this benchmark", benchCorpusEnv)
	}

	events, err := readPadataEvents(path, maxRows)
	if err != nil {
		tb.Fatalf("read corpus %s: %v", path, err)
	}
	if len(events) == 0 {
		tb.Fatalf("corpus %s yielded no events", path)
	}
	return events
}

func readPadataEvents(path string, maxRows int) ([]traceEvent, error) {
	rc, err := openMaybeCompressed(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	r := io.Reader(rc)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != padataMagic {
		return nil, errors.New("incorrect magic number")
	}
	var formatVersion, nBatches uint16
	if err := binary.Read(r, binary.BigEndian, &formatVersion); err != nil {
		return nil, fmt.Errorf("read format version: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &nBatches); err != nil {
		return nil, fmt.Errorf("read batch count: %w", err)
	}

	// Mappings are interned across the whole file, matching the tracer: the
	// same executable seen in two batches must produce one FileID, or the
	// encoders' dictionaries look artificially large.
	mappings := make(map[string]libpf.FrameMapping)

	var (
		out   []traceEvent
		frame = bytes.NewBuffer(nil)
	)
	for i := 0; i < int(nBatches); i++ {
		if maxRows > 0 && len(out) >= maxRows {
			break
		}

		rec, err := readFramedBatch(r, frame)
		if err != nil {
			// A file still being written when it was copied ends mid-batch.
			// Use what was read rather than failing the run.
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("batch %d: %w", i, err)
		}

		if v := schemaVersionOf(rec.Schema()); v != "v2" {
			rec.Release()
			return nil, fmt.Errorf("batch %d: schema %q, only v2 is supported", i, v)
		}

		events, err := eventsFromRecord(rec, mappings)
		rec.Release()
		if err != nil {
			return nil, fmt.Errorf("batch %d: %w", i, err)
		}
		out = append(out, events...)
	}

	if maxRows > 0 && len(out) > maxRows {
		out = out[:maxRows]
	}
	return out, nil
}

func openMaybeCompressed(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if filepath.Ext(path) != ".zst" {
		return f, nil
	}
	dec, err := zstd.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return zstdReadCloser{dec: dec, f: f}, nil
}

type zstdReadCloser struct {
	dec *zstd.Decoder
	f   *os.File
}

func (z zstdReadCloser) Read(p []byte) (int, error) { return z.dec.Read(p) }
func (z zstdReadCloser) Close() error {
	z.dec.Close()
	return z.f.Close()
}

// readFramedBatch reads one length-prefixed Arrow IPC stream.
func readFramedBatch(r io.Reader, buf *bytes.Buffer) (arrow.RecordBatch, error) {
	var sz uint32
	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, err
	}

	buf.Reset()
	if _, err := io.CopyN(buf, r, int64(sz)); err != nil {
		return nil, err
	}

	reader, err := ipc.NewReader(bytes.NewReader(buf.Bytes()),
		ipc.WithAllocator(memory.DefaultAllocator))
	if err != nil {
		return nil, fmt.Errorf("open ipc reader: %w", err)
	}
	defer reader.Release()

	if !reader.Next() {
		if reader.Err() != nil {
			return nil, fmt.Errorf("read record: %w", reader.Err())
		}
		return nil, errors.New("no record in batch")
	}

	rec := reader.RecordBatch()
	rec.Retain()
	return rec, nil
}

func schemaVersionOf(s *arrow.Schema) string {
	md := s.Metadata()
	for i, k := range md.Keys() {
		if k == "parca_write_schema_version" {
			return md.Values()[i]
		}
	}
	return "unknown"
}
