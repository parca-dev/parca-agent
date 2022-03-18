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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-kit/log"
	"github.com/goburrow/cache"
)

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

var fileSystem fs.FS = &realfs{}

// Finder finds the additional debug information on the system.
type Finder struct {
	logger log.Logger

	cache cache.Cache
}

// NewFinder creates a new Finder.
func NewFinder(logger log.Logger) *Finder {
	return &Finder{
		logger: log.With(logger, "component", "finder"),
		cache:  cache.New(cache.WithMaximumSize(128)), // Arbitrary cache size.
	}
}

// Find finds the debug information for the given build ID.
func (f *Finder) Find(ctx context.Context, buildID, root string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	if val, ok := f.cache.GetIfPresent(buildID); ok {
		switch v := val.(type) {
		case string:
			return v, nil
		case error:
			return "", v
		default:
			// We didn't put you there?!
			return "", errors.New("unexpected type")
		}
	}

	objFile, err := find(buildID, root)
	if err != nil {
		if errors.Is(err, errNotFound) {
			f.cache.Put(buildID, err)
			return "", err
		}
	}

	f.cache.Put(buildID, objFile)
	return objFile, nil
}

func find(buildID, root string) (string, error) {
	if len(buildID) < 2 {
		return "", errors.New("invalid build ID")
	}
	// Debian: /usr/lib/debug/.build-id/f9/02f8a561c3abdb9c8d8c859d4243bd8c3f928f.debug
	// -- apt install <package>-dbg
	// Fedora: /usr/lib/debug/.build-id/da/40581445b62eff074d67fae906792cb26e8d54.debug
	// -- dnf --enablerepo=fedora-debuginfo --enablerepo=updates-debuginfo install <package>-debuginfo
	// Arch: https://wiki.archlinux.org/title/Debugging/Getting_traces
	file := filepath.Join(root, "/usr/lib/debug", ".build-id", buildID[:2], buildID[2:]) + ".debug"
	_, err := fs.Stat(fileSystem, file)
	if err == nil {
		return file, nil
	}

	if os.IsNotExist(err) {
		return "", errNotFound
	}

	return "", fmt.Errorf("failed to search debug files: %w", err)
}
