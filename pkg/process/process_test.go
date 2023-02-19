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

package process

import (
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
)

type tProc struct {
	pid  int
	ppid int
}

func mustNewProcFS() procfs.FS {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		panic(err)
	}

	return fs
}

func newTestTree(pids ...tProc) *Tree {
	t := NewTree(
		log.NewNopLogger(),
		mustNewProcFS(),
		10*time.Second,
	)
	for _, p := range pids {
		t.tree[processKey{p.pid}] = process{
			proc:   procfs.Proc{PID: p.pid},
			parent: p.ppid,
		}
	}
	return t
}

func procToPID(procs []procfs.Proc) []int {
	pids := make([]int, len(procs))
	for i, p := range procs {
		pids[i] = p.PID
	}
	return pids
}

func Test_process_ancestors(t *testing.T) {
	t.Parallel()

	type fields struct {
		Proc procfs.Proc
		tree *Tree
	}

	multiNodeTree := newTestTree(
		tProc{pid: 1, ppid: 0}, tProc{pid: 2, ppid: 1}, tProc{pid: 3, ppid: 2},
		tProc{pid: 4, ppid: 1}, tProc{pid: 5, ppid: 4},
		tProc{pid: 6, ppid: 1}, tProc{pid: 7, ppid: 6}, tProc{pid: 8, ppid: 7},
		tProc{pid: 9, ppid: 1},
	)

	tests := []struct {
		name       string
		fields     fields
		want       []int
		shouldFail bool
	}{
		{
			name: "empty tree",
			fields: fields{
				tree: newTestTree(),
				Proc: procfs.Proc{PID: 1},
			},
			shouldFail: true,
		},
		{
			name: "1 node tree",
			fields: fields{
				tree: newTestTree(tProc{pid: 1, ppid: 0}),
				Proc: procfs.Proc{PID: 1},
			},
			want: []int{},
		},
		{
			name: "1 node tree, non-existent node",
			fields: fields{
				tree: newTestTree(tProc{pid: 1, ppid: 0}),
				Proc: procfs.Proc{PID: 2},
			},
			shouldFail: true,
		},
		{
			name: "1 node tree, non-existent parent",
			fields: fields{
				tree: newTestTree(tProc{pid: 1, ppid: 0}, tProc{pid: 2, ppid: 3}),
				Proc: procfs.Proc{PID: 2},
			},
			want: []int{},
		},
		{
			name: "multiple-node tree with several ancestors - 1",
			fields: fields{
				tree: multiNodeTree,
				Proc: procfs.Proc{PID: 3},
			},
			want: []int{2, 1},
		},
		{
			name: "multiple-node tree with several ancestors - 2",
			fields: fields{
				tree: multiNodeTree,
				Proc: procfs.Proc{PID: 7},
			},
			want: []int{6, 1},
		},
		{
			name: "multiple-node tree with several ancestors - 3",
			fields: fields{
				tree: multiNodeTree,
				Proc: procfs.Proc{PID: 9},
			},
			want: []int{1},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			k := processKey{tt.fields.Proc.PID}
			p, ok := tt.fields.tree.get(k)
			if !ok {
				if !tt.shouldFail {
					require.FailNow(t, "process.ancestors() should not fail")
				}
				return
			}

			require.Equal(t, tt.want, procToPID(tt.fields.tree.ancestorsFromCache(p)))
		})
	}
}
