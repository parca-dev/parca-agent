// Copyright 2022-2023 The Parca Authors
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
//

package objectfile

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ObjectFile represents an executable or library file.
// It handles the lifetime of the underlying file descriptor.
type ObjectFile struct {
	p *Pool

	BuildID string

	Path     string
	Size     int64
	Modtime  time.Time
	openedAt time.Time

	mtx  *sync.RWMutex
	file *os.File
	// Protected by mtx. ELF file is read using ReaderAt,
	// which means concurrent reads are allowed.
	elf      *elf.File
	closed   bool
	closedBy *runtime.Frames // Stack trace of the first Close call.

	// If exists, will be released when the parent ObjectFile is released.
	// Go GC with a finalizer works correctly even with cyclic references.
	DebugFile *ObjectFile
}

var (
	ErrNotInitialized = errors.New("file is not initialized")
	ErrAlreadyClosed  = errors.New("file is already closed")
)

// Reader returns a reader for the file.
// Parallel reads are NOT allowed. The caller must call the returned function when done with the reader.
func (o *ObjectFile) Reader() (*io.SectionReader, func(), error) {
	if o.file == nil {
		// This should never happen.
		return nil, nil, ErrNotInitialized
	}

	o.mtx.RLock()
	if o.closed {
		o.mtx.RUnlock()
		// @norelease: Should never happen!
		panic(errors.Join(ErrAlreadyClosed, fmt.Errorf("file %s is already closed (try increasing `--object-file-pool-size`) it was closed by: %s", o.Path, frames(o.closedBy))))
	}

	r := io.NewSectionReader(o.file, 0, o.Size)
	return r, func() {
		o.mtx.RUnlock()
	}, nil
}

// ELF returns the ELF file for the object file.
// Parallel reads are allowed.
func (o *ObjectFile) ELF() (*elf.File, func(), error) {
	if o.elf == nil || o.Path == "" {
		// This should never happen.
		return nil, nil, ErrNotInitialized
	}

	o.mtx.RLock()
	if o.closed {
		o.mtx.RUnlock()
		// @norelease: Should never happen!
		panic(errors.Join(ErrAlreadyClosed, fmt.Errorf("file %s is already closed (try increasing `--object-file-pool-size`) it was closed by: %s", o.Path, frames(o.closedBy))))
	}

	return o.elf, func() {
		o.mtx.RUnlock()
	}, nil
}

// close closes the underlying file descriptor.
// It is safe to call this function multiple times.
// File should only be closed once.
func (o *ObjectFile) close() error {
	if o == nil {
		return nil
	}
	if o.elf == nil {
		return nil
	}

	o.p.metrics.closeAttempts.Inc()

	o.mtx.Lock()
	defer o.mtx.Unlock()

	if o.closed {
		return errors.Join(ErrAlreadyClosed, fmt.Errorf("file %s is already closed by: %s", o.Path, frames(o.closedBy)))
	}

	if err := o.elf.Close(); err != nil {
		o.p.metrics.closed.WithLabelValues(lvError).Inc()
		o.p.metrics.keptOpenDuration.Observe(time.Since(o.openedAt).Seconds())
		return err
	}
	// Successfully closed the file.
	o.closed = true
	o.closedBy = callers()
	o.p.metrics.closed.WithLabelValues(lvSuccess).Inc()
	o.p.metrics.open.Dec()
	o.p.metrics.keptOpenDuration.Observe(time.Since(o.openedAt).Seconds())

	return nil
}

func rewind(f io.ReadSeeker) error {
	_, err := f.Seek(0, io.SeekStart)
	return err
}

func callers() *runtime.Frames {
	var (
		pcs = make([]uintptr, 20)
		n   = runtime.Callers(1, pcs)
	)
	if n == 0 {
		return nil
	}
	return runtime.CallersFrames(pcs[:n])
}

func frames(frames *runtime.Frames) string {
	if frames == nil {
		return ""
	}
	builder := strings.Builder{}
	for {
		frame, more := frames.Next()
		builder.WriteString(fmt.Sprintf("%s (%s:%d) /", frame.Function, frame.File, frame.Line))
		if !more {
			break
		}
	}
	return builder.String()
}
