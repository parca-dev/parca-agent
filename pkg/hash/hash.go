// Copyright 2021 The Parca Authors
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

package hash

import (
	"encoding/hex"
	"hash"
	"io"
	"io/fs"

	"github.com/minio/highwayhash"
)

// TODO(brancz): Use own key, this is the example key.
var key = mustDecode("000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000")

func mustDecode(key string) []byte {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		panic("Cannot decode hex key: " + err.Error())
	}
	return keyBytes
}

func New() (hash.Hash64, error) {
	hash, err := highwayhash.New64(key)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func File(fs fs.FS, file string) (uint64, error) {
	f, err := fs.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return Reader(f)
}

func Reader(r io.Reader) (uint64, error) {
	h, err := New()
	if err != nil {
		return 0, err
	}

	_, err = io.Copy(h, r)
	return h.Sum64(), err
}
