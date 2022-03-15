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
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-kit/log"
	"github.com/goburrow/cache"

	"github.com/parca-dev/parca-agent/pkg/buildid"
)

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
	var (
		found = false
		file  string
	)
	// TODO(kakkoyun): Distros may have different locations for debuginfo files.
	// Add support for all of them. Add an issue fir this.
	err := filepath.Walk(path.Join(root, "/usr/lib/debug"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			id, err := buildid.BuildID(path)
			if err != nil {
				return fmt.Errorf("failed to extract elf build ID, %w", err)
			}
			if strings.EqualFold(id, buildID) {
				found = true
				file = path
			}
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return "", errNotFound
		}

		return "", fmt.Errorf("failed to walk debug files: %w", err)
	}

	if !found {
		return "", errNotFound
	}
	return file, nil
}
