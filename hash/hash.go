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

func newHash() (hash.Hash64, error) {
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

	h, err := newHash()
	if err != nil {
		return 0, err
	}

	_, err = io.Copy(h, f)
	return h.Sum64(), err
}
