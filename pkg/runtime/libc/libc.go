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
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/procfs"
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
			}
			if isMusl(pathname) {
				imp = LibcMusl
				libcPath = pathname
				found = true
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no libc implementation found")
	}

	path := absolutePath(proc, libcPath)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

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
var glibcMatcher = regexp.MustCompile(`^/lib(?:64)?/ld-linux-(.*).so.2`)

func isGlibc(path string) bool {
	return glibcMatcher.MatchString(path)
}

// ❯ docker run -it --rm alpine sh -c 'ldd /bin/ls'
//
//	/lib/ld-musl-x86_64.so.1 (0x71b18cdd3000)
//	libc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x71b18cdd3000)
var muslMatcher = regexp.MustCompile(`^/lib(?:64)?/ld-musl-(.*).so.1$`)

func isMusl(path string) bool {
	return muslMatcher.MatchString(path)
}

// GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.6) stable release version 2.35.
// Copyright (C) 2022 Free Software Foundation, Inc.
// This is free software; see the source for copying conditions.
// There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE.
// Compiled by GNU CC version 11.4.0.
// libc ABIs: UNIQUE IFUNC ABSOLUTE
// For bug reporting instructions, please see:
// <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
var glibcVersionMatcher = regexp.MustCompile(`^GNU C Library \(.* GLIBC (.*?)\).*\.$`)

func glibcVersion(r io.Reader) (*semver.Version, error) {
	buf := make([]byte, 1024)
	if _, err := io.ReadAtLeast(r, buf, 128); err != nil {
		return nil, fmt.Errorf("read buffer: %w", err)
	}

	for _, line := range bytes.Split(buf, []byte("\n")) {
		if matches := glibcVersionMatcher.FindSubmatch(line); matches != nil {
			v, err := semver.NewVersion(string(matches[1]))
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
	}
	return nil, fmt.Errorf("version not found")
}

// musl libc (x86_64)
// Version 1.2.4_git20230717
// Dynamic Program Loader
// Usage: /lib/ld-musl-x86_64.so.1 [options] [--] pathname [args]
var muslVersionMatcher = regexp.MustCompile(`^Version (.*?)$`)

func muslVersion(r io.Reader) (*semver.Version, error) {
	buf := make([]byte, 1024)
	if _, err := io.ReadAtLeast(r, buf, 128); err != nil {
		return nil, fmt.Errorf("read buffer: %w", err)
	}
	for _, line := range bytes.Split(buf, []byte("\n")) {
		if matches := muslVersionMatcher.FindSubmatch(line); matches != nil {
			rawVersion := strings.Split(string(matches[1]), "_")[0]
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
	}
	return nil, fmt.Errorf("version not found")
}

func absolutePath(proc procfs.Proc, p string) string {
	return path.Join("/proc/", strconv.Itoa(proc.PID), "/root/", p)
}
