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

// This package includes modified code from the github.com/google/pprof/internal/binutils

package objectfile

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.uber.org/atomic"
)

// elfOpen    = elf.Open.
var elfNewFile = elf.NewFile

// ObjectFile represents an executable or library file.
// It handles the lifetime of the underlying file descriptor.
type ObjectFile struct {
	BuildID string

	Path    string
	File    *os.File
	Size    int64
	Modtime time.Time

	// Opened using elf.NewFile.
	// Closing should be done using File.Close.
	ElfFile *elf.File

	closed *atomic.Bool
}

func (o *ObjectFile) IsOpen() bool {
	return o != nil && o.File != nil && !o.closed.Load()
}

func (o *ObjectFile) ReOpen() error {
	f, err := os.Open(o.Path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", o.Path, err)
	}
	closer := func(err error) error {
		if cErr := f.Close(); cErr != nil {
			err = errors.Join(err, cErr)
		}
		return err
	}

	ok, err := isELF(f)
	if err != nil {
		return closer(fmt.Errorf("failed check whether file is an ELF file %s: %w", o.Path, err))
	}
	if !ok {
		return closer(fmt.Errorf("unrecognized binary format: %s", o.Path))
	}
	ef, err := elfNewFile(f)
	if err != nil {
		return closer(fmt.Errorf("error opening %s: %w", o.Path, err))
	}
	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat the file: %w", err)
	}
	o.File = f
	o.ElfFile = ef
	o.Size = stat.Size()
	o.Modtime = stat.ModTime()
	o.closed.Store(false)
	return nil
}

func (o *ObjectFile) Rewind() error {
	if err := rewind(o.File); err != nil {
		return fmt.Errorf("failed to seek to the beginning of the file %s: %w", o.Path, err)
	}
	return nil
}

func rewind(f io.ReadSeeker) error {
	_, err := f.Seek(0, io.SeekStart)
	return err
}

func (o *ObjectFile) Close() error {
	if o == nil {
		return nil
	}
	if o.closed.Load() {
		return nil
	}

	var err error
	if o.File != nil {
		err = errors.Join(err, o.File.Close())
	}
	o.closed.Store(true)
	return err
}

// isELF opens a file to check whether its format is ELF.
func isELF(f *os.File) (_ bool, err error) {
	defer func() {
		if rErr := rewind(f); rErr != nil {
			err = errors.Join(err, rErr)
		}
	}()

	// Read the first 4 bytes of the file.
	var header [4]byte
	if _, err := f.Read(header[:]); err != nil {
		return false, fmt.Errorf("error reading magic number from %s: %w", f.Name(), err)
	}

	// Match against supported file types.
	isELFMagic := string(header[:]) == elf.ELFMAG
	return isELFMagic, nil
}

func (o *ObjectFile) HasTextSection() bool {
	if textSection := o.ElfFile.Section(".text"); textSection == nil {
		return false
	}
	return true
}
