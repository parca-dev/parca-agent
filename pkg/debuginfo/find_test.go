// Copyright (c) 2022 The Parca Authors
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
	"testing"

	"github.com/go-kit/log"
	"github.com/goburrow/cache"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

type fakeCache struct {
	cache.Cache
}

func TestFinderWithFakeFS_find(t *testing.T) {
	oldFs := fileSystem
	mfs := testutil.NewFakeFS(map[string][]byte{
		"/proc/124/root/usr/lib/debug/.build-id/d1/b25b63b3edc63832fd885e4b997f8a463ea573.debug": []byte("whatever"),
	})
	fileSystem = mfs
	t.Cleanup(func() {
		fileSystem = oldFs
	})
	type args struct {
		root    string
		buildID string
		path    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				buildID: "",
				root:    "",
				path:    "",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				buildID: "d1b25b63b3edc63832fd885e4b997f8a463ea573",
				root:    "/proc/124/root",
				path:    "/proc/124/root/bin/parca",
			},
			want: "/proc/124/root/usr/lib/debug/.build-id/d1/b25b63b3edc63832fd885e4b997f8a463ea573.debug",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finder{
				logger:    log.NewNopLogger(),
				cache:     fakeCache{},
				debugDirs: defaultDebugDirs,
			}
			got, err := f.find(tt.args.root, tt.args.buildID, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFinder_find(t *testing.T) {
	type args struct {
		root    string
		buildID string
		path    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "with .gnu_debuglink specified",
			args: args{
				root:    "testdata",
				buildID: "somebuildidthatdoesntmatterinthiscase",
				path:    "testdata/readelf-sections",
			},
			want: "testdata/readelf-sections.debug",
		},
		{
			name: "with .gnu_debuglink specified but linked file mismatches",
			args: args{
				root:    "testdata",
				buildID: "somebuildidthatdoesntmatterinthiscase",
				path:    "testdata/readelf-sections-invalid",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finder{
				logger:    log.NewNopLogger(),
				cache:     fakeCache{},
				debugDirs: defaultDebugDirs,
			}
			got, err := f.find(tt.args.root, tt.args.buildID, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFinder_generatePaths(t *testing.T) {
	type fields struct {
		debugDirs []string
	}
	type args struct {
		root    string
		buildID string
		path    string
		base    string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []string
	}{
		//		- /usr/lib/debug/.build-id/ab/cdef1234.debug
		//		- /usr/bin/ls.debug
		//		- /usr/bin/.debug/ls.debug
		//		- /usr/lib/debug/usr/bin/ls.debug
		{
			name: "simple",

			fields: fields{
				debugDirs: defaultDebugDirs,
			},
			args: args{
				root:    "/",
				buildID: "abcdef1234",
				path:    "bin/ls",
				base:    "",
			},
		},
		{
			name: "default",
			fields: fields{
				debugDirs: defaultDebugDirs,
			},
			args: args{
				root:    "/proc/124/root",
				buildID: "d1b25b63b3edc63832fd885e4b997f8a463ea573",
				path:    "/proc/124/root/bin/foo",
				base:    "",
			},
			want: []string{
				"/proc/124/root/bin/foo.debug",
				"/proc/124/root/bin/.debug/foo.debug",
				"/proc/124/root/usr/lib/debug/bin/foo.debug",
				"/proc/124/root/usr/lib/debug/.build-id/d1/b25b63b3edc63832fd885e4b997f8a463ea573.debug",
			},
		},
		{
			name: "with custom global debug file dir",
			fields: fields{
				debugDirs: []string{"/custom/global/debug"},
			},
			args: args{
				root:    "/proc/124/root",
				buildID: "d1b25b63b3edc63832fd885e4b997f8a463ea573",
				path:    "/proc/124/root/bin/foo",
			},
			want: []string{
				"/proc/124/root/bin/foo.debug",
				"/proc/124/root/bin/.debug/foo.debug",
				"/proc/124/root/custom/global/debug/bin/foo.debug",
				"/proc/124/root/custom/global/debug/.build-id/d1/b25b63b3edc63832fd885e4b997f8a463ea573.debug",
			},
		},
		{
			name: "with base specified",
			fields: fields{
				debugDirs: defaultDebugDirs,
			},
			args: args{
				root:    "/proc/124/root",
				buildID: "somebuildidthatdoesntmatterinthiscase",
				path:    "/proc/124/root/bin/foo",
				base:    "bar.debug",
			},
			want: []string{
				"/proc/124/root/bin/bar.debug",
				"/proc/124/root/bin/.debug/bar.debug",
				"/proc/124/root/usr/lib/debug/bin/bar.debug",
				"/proc/124/root/usr/lib/debug/.build-id/so/mebuildidthatdoesntmatterinthiscase.debug",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finder{
				logger:    log.NewNopLogger(),
				cache:     fakeCache{},
				debugDirs: tt.fields.debugDirs,
			}
			require.Equal(t, tt.want, f.generatePaths(tt.args.root, tt.args.buildID, tt.args.path, tt.args.base))
		})
	}
}

func Test_readDebuglink(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name     string
		args     args
		wantBase string
		wantSum  uint32
		wantErr  bool
	}{
		{
			name: "valid",
			args: args{
				path: "testdata/readelf-sections",
			},
			wantBase: "readelf-sections.debug",
			wantSum:  2366737317, // needs to be changed if testdata/generate.sh runs
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotSum, err := readDebuglink(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("readDebuglink() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantBase {
				t.Errorf("readDebuglink() got = %v, want %v", got, tt.wantBase)
			}
			if gotSum != tt.wantSum {
				t.Errorf("readDebuglink() gotSum = %v, want %v", gotSum, tt.wantSum)
			}
		})
	}
}
