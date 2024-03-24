// Copyright 2022-2024 The Parca Authors
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

package unwind

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/Masterminds/semver/v3"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/erlang"
	"github.com/parca-dev/parca-agent/pkg/runtime/nodejs"
)

// The inode value can be recycled (this behavior is filesystem specific)
// and it's only guaranteed to be unique within each filesystem. By adding
// the change time, which gets updated every time the file or its medatadata
// are modified + the inode we significantly reduce the chances of collisions.
//
// Replacing the file in-place might result in the same inode being used, but
// the change time will most likely be different.
type framePointerCacheKey struct {
	inode        uint64
	creationTime syscall.Timespec
}

type FramePointerDetectionResult struct {
	OnlyMainExecutable bool
	AllMappings        bool
}

type FramePointerDetector struct {
	cache        *cache.Cache[framePointerCacheKey, FramePointerDetectionResult]
	compilerInfo *runtime.CompilerInfoManager
}

func NewFramePointerDetector(logger log.Logger, reg prometheus.Registerer, cim *runtime.CompilerInfoManager) *FramePointerDetector {
	return &FramePointerDetector{
		// 8 bytes for the hash + 3 * 8 bytes for the actual key (inode: uint64
		// syscall.Timespec: 2x int64) + size of value (bool: 1x byte)
		// => 33 bytes
		// => 33 bytes * 10_000 entries = 0.330 KB (excluding metadata from the map).
		cache: cache.NewLRUCache[framePointerCacheKey, FramePointerDetectionResult](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "frame_pointer"}, reg),
			10_000,
		),
		compilerInfo: cim,
	}
}

func (fpc *FramePointerDetector) cacheKey(executable string) (framePointerCacheKey, error) {
	fileinfo, err := os.Stat(executable)
	if err != nil {
		return framePointerCacheKey{}, err
	}

	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return framePointerCacheKey{}, errors.New("fileinfo didn't have stat_t")
	}

	return framePointerCacheKey{
		inode:        stat.Ino,
		creationTime: stat.Ctim,
	}, nil
}

func (fpc *FramePointerDetector) HasFramePointers(executable string) (FramePointerDetectionResult, error) {
	res := FramePointerDetectionResult{}
	cacheKey, err := fpc.cacheKey(executable)
	if err != nil {
		return res, err
	}

	if cachedHasFramePointers, found := fpc.cache.Get(cacheKey); found {
		return cachedHasFramePointers, nil
	}

	res, err = fpc.hasFramePointers(executable)
	if err != nil {
		return res, err
	}
	fpc.cache.Add(cacheKey, res)
	return res, nil
}

func (fpc *FramePointerDetector) hasFramePointers(executable string) (FramePointerDetectionResult, error) {
	res := FramePointerDetectionResult{}
	compiler, err := fpc.compilerInfo.Fetch(executable)
	if err != nil {
		return res, fmt.Errorf("failed to get compiler info for %s: %w", executable, err)
	}

	// Go 1.7 [0] enabled FP for x86_64. arm64 got them enabled in 1.12 [1].
	//
	// Note: we don't take into account applications that use cgo yet.
	// If the non Go bits aren't compiled with frame pointers, too,
	// unwinding will fail. In the future might add the unwind information
	// for these bits of executable code.
	//
	// [0]: https://go.dev/doc/go1.7 (released on 2016-08-15).
	// [1]: https://go.dev/doc/go1.12 (released on 2019-02-25).
	if strings.Contains(compiler.Type, "Go") {
		v := "1.12.0"
		want, err := semver.NewVersion(v)
		if err != nil {
			return res, fmt.Errorf("failed to parse (%s) semver: %w", v, err)
		}

		compilerVersion, err := semver.NewVersion(compiler.Version)
		if err != nil {
			return res, fmt.Errorf("failed to parse semver for the compiler (%s): %w", compiler.Version, err)
		}

		// For Go, we can only guarantee that the main executable has frame pointers.
		// For the CGO or a binary linked against libc we can't guarantee that.
		res.OnlyMainExecutable = want.LessThan(compilerVersion)
		return res, nil
	}

	// v8 uses a custom code generator for some of it's ahead-of-time functions. They do contain
	// frame pointers, but no DWARF unwind information, so we force frame pointer unwinding as
	// mixed mode unwinding (fp -> DWARF) won't work here.
	isV8, err := nodejs.IsV8(executable)
	if err != nil {
		return res, fmt.Errorf("check if executable is the V8: %w", err)
	}
	if isV8 {
		res.AllMappings = true
		return res, nil
	}

	isBEAM, err := erlang.IsBEAM(executable)
	if err != nil {
		return res, fmt.Errorf("check if executable is the BEAM: %w", err)
	}
	if isBEAM {
		res.AllMappings = true
		return res, nil
	}

	// TODO(kakkoyun): Add Corretto detection.

	// By default, assume there frame pointers are not present.
	return res, nil
}
