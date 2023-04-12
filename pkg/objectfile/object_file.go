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

	"github.com/parca-dev/parca-agent/pkg/buildid"
)

var (
	elfOpen    = elf.Open
	elfNewFile = elf.NewFile
)

// ObjectFile represents an executable or library file.
// It handles the lifetime of the underlying file descriptor.
type ObjectFile struct {
	BuildID string

	Path string

	File    *os.File
	Size    int64
	Modtime time.Time
	// Opened using elf.NewFile.
	// Closing should be done using File.Close.
	ElfFile *elf.File

	DebuginfoFile *ObjectFile
}

// Open opens the specified executable or library file from the given path.
func Open(filePath string) (*ObjectFile, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening %s: %w", filePath, err)
	}
	return NewFile(f)
}

// NewFile creates a new ObjectFile from an existing file.
func NewFile(f *os.File) (*ObjectFile, error) {
	closer := func(err error) error {
		if cErr := f.Close(); cErr != nil {
			err = errors.Join(err, cErr)
		}
		return err
	}
	filePath := f.Name()
	ok, err := isELF(f)
	if err != nil {
		return nil, closer(err)
	}
	if !ok {
		return nil, closer(fmt.Errorf("unrecognized binary format: %s", filePath))
	}
	ef, err := elfNewFile(f)
	if err != nil {
		return nil, closer(fmt.Errorf("error opening %s: %w", filePath, err))
	}

	buildID := ""
	if id, err := buildid.BuildID(f, ef); err == nil {
		buildID = id
	}
	if rErr := rewind(f); rErr != nil {
		return nil, closer(rErr)
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat the file: %w", err)
	}

	return &ObjectFile{
		BuildID: buildID,
		Path:    filePath,
		File:    f,
		ElfFile: ef,
		Size:    stat.Size(),
		Modtime: stat.ModTime(),
	}, nil
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
	var err error
	if o != nil && o.File != nil {
		err = errors.Join(err, o.File.Close())
	}
	// No need to close o.ElfFile as it is closed by o.File.Close.
	if o != nil && o.DebuginfoFile != nil && o.DebuginfoFile != o {
		err = errors.Join(err, o.DebuginfoFile.Close())
	}
	return err
}
