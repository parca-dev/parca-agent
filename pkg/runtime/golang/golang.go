// Copyright 2024 The Parca Authors
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

package golang

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/runtime"
)

type GoCustomLabelOffsets struct {
	M      uint32
	Curg   uint32
	Labels uint32

	HmapCount           uint32
	HmapLog2BucketCount uint32
	HmapBuckets         uint32
}

// TODO[btv] Someday we will also store custom label
// offsets for other runtimes here, but for now it's just go.
type CustomLabelOffsetsCache struct {
	cache        *cache.Cache[string, GoCustomLabelOffsets]
	compilerInfo *runtime.CompilerInfoManager
}

func NewCustomLabelOffsetsCache(reg prometheus.Registerer, cim *runtime.CompilerInfoManager) CustomLabelOffsetsCache {
	return CustomLabelOffsetsCache{
		cache: cache.NewLRUCache[string, GoCustomLabelOffsets](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "custom_labels"}, reg),
			10_000,
		),
		compilerInfo: cim,
	}
}

func ReadOffsets(path string) (GoCustomLabelOffsets, error) {
	f, err := elf.Open(path)
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	d, err := f.DWARF()
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	r := d.Reader()
	g, err := util.ReadEntry(r, "runtime.g", dwarf.TagStructType)
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}
	if g == nil {
		return GoCustomLabelOffsets{}, fmt.Errorf("type runtime.g not found")
	}

	mPType, mOffset, err := util.ReadChildTypeAndOffset(r, "m")
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	if mPType.Tag != dwarf.TagPointerType {
		return GoCustomLabelOffsets{}, fmt.Errorf("type of m in runtime.g is not a pointer")
	}

	_, err = util.ReadType(r, mPType)
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	curgPType, curgOffset, err := util.ReadChildTypeAndOffset(r, "curg")
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	if curgPType.Tag != dwarf.TagPointerType {
		return GoCustomLabelOffsets{}, fmt.Errorf("curg type is not a pointer")
	}

	_, err = util.ReadType(r, curgPType)
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	_, labelsOffset, err := util.ReadChildTypeAndOffset(r, "labels")
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	hmap, err := util.ReadEntry(r, "runtime.hmap", dwarf.TagStructType)
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}
	if hmap == nil {
		return GoCustomLabelOffsets{}, fmt.Errorf("type runtime.hmap not found")
	}

	_, countOffset, err := util.ReadChildTypeAndOffset(r, "count")
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}
	r.Seek(hmap.Offset)
	r.Next()
	_, bOffset, err := util.ReadChildTypeAndOffset(r, "B")
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}
	r.Seek(hmap.Offset)
	r.Next()
	_, bucketsOffset, err := util.ReadChildTypeAndOffset(r, "buckets")
	if err != nil {
		return GoCustomLabelOffsets{}, err
	}

	return GoCustomLabelOffsets{
		M:                   uint32(mOffset),
		Curg:                uint32(curgOffset),
		Labels:              uint32(labelsOffset),
		HmapCount:           uint32(countOffset),
		HmapLog2BucketCount: uint32(bOffset),
		HmapBuckets:         uint32(bucketsOffset),
	}, nil
}

func (cloc *CustomLabelOffsetsCache) Fetch(executable string) (*GoCustomLabelOffsets, error) {
	if gclo, found := cloc.cache.Get(executable); found {
		return &gclo, nil
	}

	compiler, err := cloc.compilerInfo.Fetch(executable)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(compiler.Type, "Go") {
		return nil, nil
	}
	// custom labels were added in 1.9
	want, err := semver.NewVersion("1.9.0")
	if err != nil {
		panic(err)
	}
	compilerVersion, err := semver.NewVersion(compiler.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semver for the compiler (%s): %w", compiler.Version, err)
	}
	if compilerVersion.LessThan(want) {
		return nil, nil
	}

	gclo, err := ReadOffsets(executable)
	if err != nil {
		return nil, err
	}
	cloc.cache.Add(executable, gclo)

	return &gclo, nil
}
