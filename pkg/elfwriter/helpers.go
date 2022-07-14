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

package elfwriter

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
)

func writeFrom(w io.Writer, r io.Reader) (uint64, uint64, error) {
	if r == nil {
		return 0, 0, errors.New("reader is nil")
	}

	pr, pw := io.Pipe()

	// write in writer end of pipe.
	var wErr error
	var read int64
	go func() {
		defer pw.Close()
		defer func() {
			if r := recover(); r != nil {
				debug.PrintStack()
				err, ok := r.(error)
				if ok {
					wErr = fmt.Errorf("panic occurred: %w", err)
				}
			}
		}()
		read, wErr = io.Copy(pw, r)
	}()

	// read from reader end of pipe.
	defer pr.Close()
	written, rErr := io.Copy(w, pr)
	if wErr != nil {
		return 0, 0, wErr
	}
	if rErr != nil {
		return 0, 0, rErr
	}

	return uint64(written), uint64(read), nil
}

func writeFromCompressed(w io.Writer, r io.Reader) (uint64, uint64, error) {
	if r == nil {
		return 0, 0, errors.New("reader is nil")
	}

	pr, pw := io.Pipe()

	// write in writer end of pipe.
	var wErr error
	var read int64
	go func() {
		defer pw.Close()
		defer func() {
			if r := recover(); r != nil {
				debug.PrintStack()
				err, ok := r.(error)
				if ok {
					wErr = fmt.Errorf("panic occurred: %w", err)
				}
			}
		}()
		read, wErr = io.Copy(pw, r)
	}()

	// read from reader end of pipe.
	defer pr.Close()

	buf := bytes.NewBuffer(nil)
	zw := zlib.NewWriter(buf)
	if _, err := io.Copy(zw, pr); err != nil {
		zw.Close()
		return 0, 0, err
	}
	zw.Close()

	if wErr != nil {
		return 0, 0, wErr
	}

	written, err := w.Write(buf.Bytes())
	if err != nil {
		return 0, 0, err
	}

	return uint64(written), uint64(read), nil
}
