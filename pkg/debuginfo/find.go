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

package debuginfo

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

var fileSystem fs.FS = &realfs{}

// Finder finds the separate debug information files on the system.
type Finder struct {
	logger log.Logger

	cache     burrow.Cache
	debugDirs []string
}

// NewFinder creates a new Finder.
func NewFinder(logger log.Logger, reg prometheus.Registerer, debugDirs []string) *Finder {
	return &Finder{
		logger: log.With(logger, "component", "finder"),
		cache: burrow.New(
			burrow.WithMaximumSize(128),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "debuginfo_find")),
		), // Arbitrary cache size.
		debugDirs: debugDirs,
	}
}

func (f *Finder) Close() error {
	return f.cache.Close()
}

// Find finds the separate debug file for the given object file.
func (f *Finder) Find(ctx context.Context, root string, objFile *objectfile.ObjectFile) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	buildID := objFile.BuildID
	if val, ok := f.cache.GetIfPresent(buildID); ok {
		switch v := val.(type) {
		case string:
			return v, nil
		case error:
			return "", v
		default:
			// We didn't put you there?!
			return "", fmt.Errorf("unexpected type in cache: %T", val)
		}
	}

	file, err := f.find(root, objFile)
	if err != nil {
		if errors.Is(err, errNotFound) {
			f.cache.Put(buildID, err)
			return "", err
		}
	}

	f.cache.Put(buildID, file)
	return file, nil
}

var errSectionNotFound = errors.New("section not found")

func (f *Finder) find(root string, objFile *objectfile.ObjectFile) (string, error) {
	if objFile == nil {
		return "", errors.New("object file is nil")
	}
	if len(objFile.BuildID) < 2 {
		return "", errors.New("invalid build ID")
	}

	// There are two ways of specifying the separate debuginfo file:
	// 1) The executable contains a debug link that specifies the name of the separate debuginfo file.
	//	The separate debug file’s name is usually executable.debug,
	//	where executable is the name of the corresponding executable file without leading directories (e.g., ls.debug for /usr/bin/ls).
	// 2) The executable contains a build ID, a unique bit string that is also present in the corresponding debuginfo file.
	//  (This is supported only on some operating systems, when using the ELF or PE file formats for binary files and the GNU Binutils.)
	//  The debuginfo file’s name is not specified explicitly by the build ID, but can be computed from the build ID, see below.
	//
	// So, for example, suppose you ask Agent to debug /usr/bin/ls, which has a debug link that specifies the file ls.debug,
	//	and a build ID whose value in hex is abcdef1234.
	//	If the list of the global debug directories includes /usr/lib/debug (which is the default),
	//	then Finder will look for the following debug information files, in the indicated order:
	//
	//		- /usr/lib/debug/.build-id/ab/cdef1234.debug
	//		- /usr/bin/ls.debug
	//		- /usr/bin/.debug/ls.debug
	//		- /usr/lib/debug/usr/bin/ls.debug
	//
	// For further information, see: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

	// A debug link is a special section of the executable file named .gnu_debuglink. The section must contain:
	//
	// A filename, with any leading directory components removed, followed by a zero byte,
	//  - zero to three bytes of padding, as needed to reach the next four-byte boundary within the section, and
	//  - a four-byte CRC checksum, stored in the same endianness used for the executable file itself.
	// The checksum is computed on the debugging information file’s full contents by the function given below,
	// passing zero as the crc argument.

	ef, err := objFile.ELF()
	if err != nil {
		return "", fmt.Errorf("failed to read ELF file: %w", err)
	}

	base, crc, err := readDebuglink(ef)
	if err != nil {
		if !errors.Is(err, errSectionNotFound) {
			level.Debug(f.logger).Log("msg", "failed to read debug links", "err", err)
		}
	}

	files := f.generatePaths(root, objFile.BuildID, objFile.Path, base)
	if len(files) == 0 {
		return "", errors.New("failed to generate paths")
	}

	var found string
	for _, file := range files {
		_, err := fs.Stat(fileSystem, file)
		if err == nil {
			found = file
			break
		}
		if os.IsNotExist(err) {
			continue
		}
	}

	if found == "" {
		return "", errNotFound
	}

	if strings.Contains(found, ".build-id") || strings.HasSuffix(found, "/debuginfo") || crc <= 0 {
		return found, nil
	}

	match, err := checkSum(found, crc)
	if err != nil {
		return "", fmt.Errorf("failed to check checksum: %w", err)
	}

	if match {
		return found, nil
	}

	return "", errNotFound
}

func readDebuglink(ef *elf.File) (string, uint32, error) {
	if sec := ef.Section(".gnu_debuglink"); sec != nil {
		d, err := sec.Data()
		if err != nil {
			return "", 0, err
		}
		parts := bytes.Split(d, []byte{0})
		name := string(parts[0])
		sum := parts[len(parts)-1]
		if len(sum) != 4 {
			return "", 0, errors.New("invalid checksum length")
		}
		crc := ef.FileHeader.ByteOrder.Uint32(sum)
		if crc == 0 {
			return "", 0, errors.New("invalid checksum")
		}
		return name, crc, nil
	}
	return "", 0, errSectionNotFound
}

func (f *Finder) generatePaths(root, buildID, path, filename string) []string {
	const dbgExt = ".debug"
	if len(filename) == 0 {
		filename = filepath.Base(path)
	}
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = dbgExt
	}
	dbgFilePath := filepath.Join(filepath.Dir(path), strings.TrimSuffix(filename, ext)) + ext

	var files []string
	for _, dir := range f.debugDirs {
		rel, err := filepath.Rel(root, dbgFilePath)
		if err != nil {
			continue
		}
		files = append(files, []string{
			dbgFilePath,
			filepath.Join(filepath.Dir(path), dbgExt, filepath.Base(dbgFilePath)),
			filepath.Join(root, dir, rel),
			filepath.Join(root, dir, ".build-id", buildID[:2], buildID[2:]) + dbgExt,
			filepath.Join(root, dir, buildID, "debuginfo"),
		}...)
	}
	return files
}

// NOTE: we are within the race condition window, but alas.
func checkSum(path string, crc uint32) (bool, error) {
	file, err := fileSystem.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	d, err := io.ReadAll(file)
	if err != nil {
		return false, err
	}
	return crc == crc32.ChecksumIEEE(d), nil
}
