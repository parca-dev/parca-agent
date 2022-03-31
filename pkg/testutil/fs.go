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

package testutil

import (
	"bytes"
	"io"
	"io/fs"
)

type fakefile struct {
	content io.Reader
}

func (f *fakefile) Stat() (fs.FileInfo, error) { return nil, nil }
func (f *fakefile) Read(b []byte) (int, error) { return f.content.Read(b) }
func (f *fakefile) Close() error               { return nil }

type fakefs struct {
	data map[string][]byte
}

func (f *fakefs) Open(name string) (fs.File, error) {
	d, ok := f.data[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &fakefile{content: bytes.NewBuffer(d)}, nil
}

type errorfs struct{ err error }

func (f *errorfs) Open(name string) (fs.File, error) {
	return nil, f.err
}

func NewFakeFS(files map[string][]byte) fs.FS {
	return &fakefs{files}
}

func NewErrorFS(err error) fs.FS {
	return &errorfs{err}
}
