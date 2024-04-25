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

type UnwindInfoSource byte

const (
	DwarfOnly UnwindInfoSource = iota
	DwarfOrFp
	FpOnly
)

type FramePointerCache struct {
	cache        *cache.Cache[framePointerCacheKey, UnwindInfoSource]
	compilerInfo *runtime.CompilerInfoManager
}

func NewHasFramePointersCache(logger log.Logger, reg prometheus.Registerer, cim *runtime.CompilerInfoManager) FramePointerCache {
	return FramePointerCache{
		// 8 bytes for the hash + 3 * 8 bytes for the actual key (inode: uint64
		// syscall.Timespec: 2x int64) + size of value (UnwindInfoSource: 1x byte)
		// => 33 bytes
		// => 33 bytes * 10_000 entries = 0.330 KB (excluding metadata from the map).
		cache: cache.NewLRUCache[framePointerCacheKey, UnwindInfoSource](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "frame_pointer"}, reg),
			10_000,
		),
		compilerInfo: cim,
	}
}

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

func (fpc *FramePointerCache) cacheKey(executable string) (framePointerCacheKey, error) {
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

func (fpc *FramePointerCache) HasFramePointers(executable string) (UnwindInfoSource, error) {
	cacheKey, err := fpc.cacheKey(executable)
	if err != nil {
		return DwarfOnly, err
	}

	if cachedHasFramePointers, found := fpc.cache.Get(cacheKey); found {
		return cachedHasFramePointers, nil
	}

	hasFramePointers, err := fpc.hasFramePointers(executable)
	if err != nil {
		return DwarfOnly, err
	}
	fpc.cache.Add(cacheKey, hasFramePointers)
	return hasFramePointers, nil
}

func (fpc *FramePointerCache) hasFramePointers(executable string) (UnwindInfoSource, error) {
	compiler, err := fpc.compilerInfo.Fetch(executable)
	if err != nil {
		return DwarfOnly, fmt.Errorf("failed to get compiler info for %s: %w", executable, err)
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
			return DwarfOnly, fmt.Errorf("failed to parse (%s) semver: %w", v, err)
		}

		compilerVersion, err := semver.NewVersion(compiler.Version)
		if err != nil {
			return DwarfOnly, fmt.Errorf("failed to parse semver for the compiler (%s): %w", compiler.Version, err)
		}

		if want.LessThan(compilerVersion) {
			// TODO[btv] --
			//
			// Right now, we force Go binaries to
			// _only_ use FP unwinding, rather than falling back to DWARF,
			// because DWARF unwinding is buggy
			// in some edge cases. Specifically, Go switches stacks
			// when it makes a VDSO call, and we need to read the
			// old stack pointer and instruction pointer
			// (vdsoSP / vdsoPC) from `runtime.m` in a similar way to how
			// we read the trace ID.
			//
			// For now, it's much easier to just force the use of frame pointers.
			return FpOnly, nil
		}
		return DwarfOnly, nil
	}

	// v8 uses a custom code generator for some of it's ahead-of-time functions. They do contain
	// frame pointers, but no DWARF unwind information, so we force frame pointer unwinding as
	// mixed mode unwinding (fp -> DWARF) won't work here.
	isV8, err := nodejs.IsV8(executable)
	if err != nil {
		return DwarfOnly, fmt.Errorf("check if executable is v8: %w", err)
	}
	if isV8 {
		return DwarfOrFp, nil
	}

	isBEAM, err := erlang.IsBEAM(executable)
	if err != nil {
		return DwarfOnly, fmt.Errorf("check if executable is v8: %w", err)
	}
	if isBEAM {
		return DwarfOrFp, nil
	}

	// By default, assume there frame pointers are not present.
	return DwarfOnly, nil
}
