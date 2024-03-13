// Copyright 2022-2024 The Parca Authors
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

package libc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"
	"github.com/xyproto/ainur"
)

type LibcImplementation int32

const (
	LibcGlibc LibcImplementation = iota
	LibcMusl
)

type LibcInfo struct {
	Implementation LibcImplementation
	Version        *semver.Version
}

func NewLibcInfo(proc procfs.Proc) (*LibcInfo, error) {
	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("error reading process maps: %w", err)
	}
	var (
		imp      LibcImplementation
		libcPath string
		found    bool
	)
	for _, m := range maps {
		if pathname := m.Pathname; pathname != "" {
			if isGlibc(pathname) {
				imp = LibcGlibc
				libcPath = pathname
				found = true
				break
			}
			if isMusl(pathname) {
				imp = LibcMusl
				libcPath = pathname
				found = true
				break
			}
		}
	}
	if !found {
		return nil, errors.New("no libc implementation found")
	}

	f, err := os.Open(absolutePath(proc, libcPath))
	if err != nil {
		return nil, fmt.Errorf("open libc file: %w", err)
	}
	defer f.Close()

	// It is easier to get the version of the libc implementation by running the libc itself,
	// rather than scanning the file and matching the version string.
	var version *semver.Version
	switch imp {
	case LibcGlibc:
		version, err = glibcVersion(f)
		if err != nil {
			return nil, fmt.Errorf("glibc version: %w", err)
		}
	case LibcMusl:
		version, err = muslVersion(f)
		if err != nil {
			return nil, fmt.Errorf("musl version: %w", err)
		}
	}

	return &LibcInfo{
		Implementation: imp,
		Version:        version,
	}, nil
}

// ❯ docker run -it --rm ubuntu sh -c 'ldd /usr/bin/ls'
//
//	linux-vdso.so.1 (0x00007ffeb337b000)
//	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007b46d6dbc000)
//	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007b46d6a00000)
//	libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007b46d6d25000)
//	/lib64/ld-linux-x86-64.so.2 (0x00007b46d6e10000)
var glibcMatcher = regexp.MustCompile(`libc.so.6`)

func isGlibc(path string) bool {
	return glibcMatcher.MatchString(path)
}

// ❯ docker run -it --rm alpine sh -c 'ldd /bin/ls'
//
//	/lib/ld-musl-x86_64.so.1 (0x71b18cdd3000)
//	libc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x71b18cdd3000)
var muslMatcher = regexp.MustCompile(`/lib(?:64)?/ld-musl-(.*).so.1`)

func isMusl(path string) bool {
	return muslMatcher.MatchString(path)
}

var glibcVersionMatcher = regexp.MustCompile(`glibc 2\.(\d+)`)

func glibcVersion(r io.ReadSeeker) (*semver.Version, error) {
	matched, err := scanVersionBytes(r, glibcVersionMatcher)
	if err != nil {
		return nil, fmt.Errorf("scan version bytes: %w", err)
	}
	rawVersion := strings.TrimPrefix(string(matched), "glibc ")
	v, err := semver.NewVersion(rawVersion)
	if err != nil {
		return nil, fmt.Errorf("parse version: %w", err)
	}
	nv, err := v.SetMetadata("")
	if err != nil {
		return nil, fmt.Errorf("set metadata: %w", err)
	}
	nv, err = nv.SetPrerelease("")
	if err != nil {
		return nil, fmt.Errorf("set prerelease: %w", err)
	}
	return &nv, nil
}

var muslVersionMatcher = regexp.MustCompile(`1\.([0-9])\.(\d+)`)

func muslVersion(r io.ReadSeeker) (*semver.Version, error) {
	matched, err := scanVersionBytes(r, muslVersionMatcher)
	if err != nil {
		return nil, fmt.Errorf("scan version bytes: %w", err)
	}
	rawVersion := strings.Split(string(matched), "_")[0]
	v, err := semver.NewVersion(rawVersion)
	if err != nil {
		return nil, fmt.Errorf("parse version: %w", err)
	}
	nv, err := v.SetMetadata("")
	if err != nil {
		return nil, fmt.Errorf("set metadata: %w", err)
	}
	nv, err = nv.SetPrerelease("")
	if err != nil {
		return nil, fmt.Errorf("set prerelease: %w", err)
	}
	return &nv, nil
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}

func scanVersionBytes(r io.ReadSeeker, m *regexp.Regexp) ([]byte, error) {
	bufferSize := 4096
	sr, err := ainur.NewStreamReader(r, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream reader: %w", err)
	}

	for {
		b, err := sr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to read next: %w", err)
		}

		matches := m.FindSubmatchIndex(b)
		if matches == nil {
			continue
		}

		for i := 0; i < len(matches); i++ {
			if matches[i] == -1 {
				continue
			}

			if _, err := r.Seek(int64(matches[i]), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to start: %w", err)
			}

			return b[matches[i]:matches[i+1]], nil
		}
	}

	return nil, errors.New("version not found")
}
