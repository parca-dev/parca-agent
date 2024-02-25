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
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/procfs"
)

func Test_isGlibc(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "/lib/ld-linux-x86-64.so.2",
			want: true,
		},
		{
			path: "/lib/ld-linux-aarch64.so.2",
			want: true,
		},
		{
			path: "/lib64/ld-linux-x86-64.so.2",
			want: true,
		},
		{
			path: "/lib64/ld-linux-aarch64.so.2",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isGlibc(tt.path); got != tt.want {
				t.Errorf("isGlibc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isMusl(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "/lib/ld-musl-x86_64.so.1",
			want: true,
		},
		{
			path: "/lib/ld-musl-aarch64.so.1",
			want: true,
		},
		{
			path: "/lib64/ld-musl-x86_64.so.1",
			want: true,
		},
		{
			path: "/lib64/ld-musl-aarch64.so.1",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isMusl(tt.path); got != tt.want {
				t.Errorf("isMusl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_glibcVersion(t *testing.T) {
	tests := []struct {
		name    string
		r       io.Reader
		want    *semver.Version
		wantErr bool
	}{
		{
			name: "ubuntu",
			r: strings.NewReader(`GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.6) stable release version 2.35.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 11.4.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.`),
			want: semver.MustParse("2.35"),
		},
		{
			name: "debian",
			r: strings.NewReader(`GNU C Library (Debian GLIBC 2.36-9+deb12u4) stable release version 2.36.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 12.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
Minimum supported kernel: 3.2.0
For bug reporting instructions, please see:
<http://www.debian.org/Bugs/>.`),
			want: semver.MustParse("2.36"),
		},
		{
			name: "alpine",
			r: strings.NewReader(`musl libc (x86_64)
Version 1.2.4_git20230717
Dynamic Program Loader
Usage: /lib/ld-musl-x86_64.so.1 [options] [--] pathname [args]`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := glibcVersion(tt.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("glibcVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("glibcVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_muslVersion(t *testing.T) {
	tests := []struct {
		name    string
		r       io.Reader
		want    *semver.Version
		wantErr bool
	}{
		{
			name: "alpine",
			r: strings.NewReader(`musl libc (x86_64)
Version 1.2.4_git20230717
Dynamic Program Loader
Usage: /lib/ld-musl-x86_64.so.1 [options] [--] pathname [args]`),
			want: semver.MustParse("1.2.4"),
		},
		{
			name: "debian",
			r: strings.NewReader(`GNU C Library (Debian GLIBC 2.36-9+deb12u4) stable release version 2.36.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 12.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
Minimum supported kernel: 3.2.0
For bug reporting instructions, please see:
<http://www.debian.org/Bugs/>.`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := muslVersion(tt.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("muslVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("muslVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_absolutePath(t *testing.T) {
	type args struct {
		proc procfs.Proc
		p    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := absolutePath(tt.args.proc, tt.args.p); got != tt.want {
				t.Errorf("absolutePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
