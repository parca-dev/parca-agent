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

	"github.com/parca-dev/parca-agent/pkg/testutil"
)

func Test_find(t *testing.T) {
	oldFs := fileSystem
	mfs := testutil.NewFakeFS(map[string][]byte{
		"/proc/124/root/usr/lib/debug/.build-id/d1/b25b63b3edc63832fd885e4b997f8a463ea573.debug": []byte("whatever"),
	})
	fileSystem = mfs
	t.Cleanup(func() {
		fileSystem = oldFs
	})

	type args struct {
		buildID string
		root    string
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
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				buildID: "d1b25b63b3edc63832fd885e4b997f8a463ea573",
				root:    "/proc/124/root",
			},
			want:    "/proc/124/root/usr/lib/debug/.build-id/d1/b25b63b3edc63832fd885e4b997f8a463ea573.debug",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := find(tt.args.buildID, tt.args.root)
			if (err != nil) != tt.wantErr {
				t.Errorf("find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("find() got = %v, want %v", got, tt.want)
			}
		})
	}
}
