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
	"os"
	"reflect"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-cmp/cmp"
)

func Test_isGlibc(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "/lib/x86_64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			path: "/lib/aarch64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			path: "/usr/lib/x86_64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			path: "/lib64/x86_64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			path: "/lib64/aarch64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			path: "aarch64-linux-gnu/libc.so.6",
			want: true,
		},
		{
			path: "/usr/lib/libc.so.6",
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
		path    string
		want    *semver.Version
		wantErr bool
	}{
		{
			name: "debian",
			path: "testdata/amd64/glibc.so",
			want: semver.MustParse("2.36"),
		},
		{
			name: "debian",
			path: "testdata/arm64/glibc.so",
			want: semver.MustParse("2.36"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := glibcVersion(r)
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
		path    string
		want    *semver.Version
		wantErr bool
	}{
		{
			name: "alpine",
			path: "testdata/amd64/musl.so",
			want: semver.MustParse("1.2.4"),
		},
		{
			name: "alpine",
			path: "testdata/arm64/musl.so",
			want: semver.MustParse("1.2.4"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := muslVersion(r)
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
