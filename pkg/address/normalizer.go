// Copyright 2022 The Parca Authors
// TODO: This license is not consistent with license used in the project.
//       Delete the inconsistent license and above line and rerun pre-commit to insert a good license.
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

package address

import (
	"errors"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"

	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type ObjectFileCache interface {
	ObjectFileForProcess(pid int, m *profile.Mapping) (*objectfile.MappedObjectFile, error)
}

// normalizer is a normalizer that converts memory addresses to position-independent addresses.
type normalizer struct {
	logger log.Logger

	objCache ObjectFileCache
}

// NewNormalizer creates a new AddressNormalizer.
func NewNormalizer(logger log.Logger, objCache ObjectFileCache) *normalizer {
	return &normalizer{
		logger:   logger,
		objCache: objCache,
	}
}

// Normalize calculates the base addresses of a position-independent binary and normalizes captured locations accordingly.
func (n *normalizer) Normalize(pid int, m *profile.Mapping, addr uint64) uint64 {
	if m == nil {
		return addr
	}

	logger := log.With(n.logger, "pid", pid, "buildID", m.BuildID)
	if m.Unsymbolizable() {
		return addr
	}

	objFile, err := n.objCache.ObjectFileForProcess(pid, m)
	if err != nil {
		if !(errors.Is(err, objectfile.ErrNoFile) || errors.Is(err, os.ErrNotExist)) {
			level.Debug(logger).Log("msg", "failed to open object file", "err", err)
		}
		return addr
	}

	// Transform the address using calculated base address for the binary.
	normalizedAddr, err := objFile.ObjAddr(addr)
	if err != nil {
		level.Debug(logger).Log("msg", "failed to get normalized address from object file", "err", err)
		return addr
	}

	return normalizedAddr
}
