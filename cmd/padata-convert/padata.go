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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/klauspost/compress/zstd"
)

// padataMagic prefixes every offline-mode file.
const padataMagic uint32 = 0xA6E7CCCA

// padataFile is one decoded offline-mode log: a header plus a run of Arrow IPC
// batches, each length-prefixed with a big-endian uint32.
//
// The v1 layout writes two batches per record (samples, then the stacktraces
// those samples reference); v2 records are self-contained and write one. The
// header's format version does not distinguish them -- it is 0 in both cases --
// so the schema metadata key parca_write_schema_version is what tells them
// apart.
type padataFile struct {
	Path          string
	FormatVersion uint16
	NBatches      uint16
	SchemaVersion string
	Batches       []arrow.Record
	// RawBytes is the total size of the framed IPC payloads, excluding the
	// 8-byte header and the 4-byte length prefixes. This is the number to
	// compare an OTLP encoding against.
	RawBytes int64
}

func (p *padataFile) Release() {
	for _, r := range p.Batches {
		r.Release()
	}
	p.Batches = nil
}

// openMaybeCompressed transparently handles the .zst files the rotation loop
// produces alongside the live .padata one.
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

// readPadata decodes an offline-mode file. maxBatches caps how many sample
// batches are decoded (0 means all), which keeps a 67 MB file tractable when
// sampling the corpus.
func readPadata(path string, mem memory.Allocator, maxBatches int) (*padataFile, error) {
	rc, err := openMaybeCompressed(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	r := io.Reader(rc)
	out := &padataFile{Path: path}

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != padataMagic {
		return nil, errors.New("incorrect magic number")
	}
	if err := binary.Read(r, binary.BigEndian, &out.FormatVersion); err != nil {
		return nil, fmt.Errorf("read format version: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &out.NBatches); err != nil {
		return nil, fmt.Errorf("read batch count: %w", err)
	}

	buf := bytes.NewBuffer(nil)
	for i := 0; i < int(out.NBatches); i++ {
		if maxBatches > 0 && len(out.Batches) >= maxBatches {
			break
		}

		rec, n, err := readFramedBatch(r, buf, mem)
		if err != nil {
			// A file the agent was still writing when it was copied ends
			// mid-batch. Report what we got rather than failing the run.
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("batch %d: %w", i, err)
		}
		out.RawBytes += n

		if out.SchemaVersion == "" {
			out.SchemaVersion = schemaVersionOf(rec.Schema())
		}
		out.Batches = append(out.Batches, rec)

		// v1 follows each sample batch with a stacktrace batch. It is
		// counted toward RawBytes because it is part of what v1 costs, but
		// it is not a sample record.
		if out.SchemaVersion == "v1" {
			stRec, stN, err := readFramedBatch(r, buf, mem)
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("batch %d stacktraces: %w", i, err)
			}
			out.RawBytes += stN
			stRec.Release()
		}
	}

	return out, nil
}

// readFramedBatch reads one length-prefixed Arrow IPC stream and returns the
// single record in it plus the payload size.
func readFramedBatch(r io.Reader, buf *bytes.Buffer, mem memory.Allocator) (arrow.Record, int64, error) {
	var sz uint32
	if err := binary.Read(r, binary.BigEndian, &sz); err != nil {
		return nil, 0, err
	}

	buf.Reset()
	if _, err := io.CopyN(buf, r, int64(sz)); err != nil {
		return nil, 0, err
	}

	reader, err := ipc.NewReader(bytes.NewReader(buf.Bytes()), ipc.WithAllocator(mem))
	if err != nil {
		return nil, 0, fmt.Errorf("open ipc reader: %w", err)
	}
	defer reader.Release()

	if !reader.Next() {
		if reader.Err() != nil {
			return nil, 0, fmt.Errorf("read record: %w", reader.Err())
		}
		return nil, 0, errors.New("no record in batch")
	}

	rec := reader.Record()
	rec.Retain()
	return rec, int64(sz), nil
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

// writeIPC serializes a record as a standalone Arrow IPC stream, matching how
// the offline writer frames it. Used to measure the arrow side after a
// round trip.
func writeIPC(rec arrow.Record, mem memory.Allocator, lz4 bool) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	opts := []ipc.Option{ipc.WithSchema(rec.Schema()), ipc.WithAllocator(mem)}
	if lz4 {
		opts = append(opts, ipc.WithLZ4())
	}
	w := ipc.NewWriter(buf, opts...)
	if err := w.Write(rec); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readFramedBatchRaw reads one record from an unframed IPC payload, for callers
// that already hold the bytes.
func readFramedBatchRaw(payload []byte, mem memory.Allocator) (arrow.Record, error) {
	reader, err := ipc.NewReader(bytes.NewReader(payload), ipc.WithAllocator(mem))
	if err != nil {
		return nil, fmt.Errorf("open ipc reader: %w", err)
	}
	defer reader.Release()

	if !reader.Next() {
		if reader.Err() != nil {
			return nil, fmt.Errorf("read record: %w", reader.Err())
		}
		return nil, errors.New("no record in payload")
	}

	rec := reader.Record()
	rec.Retain()
	return rec, nil
}
