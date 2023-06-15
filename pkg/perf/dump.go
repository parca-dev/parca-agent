// Copyright 2023 The Parca Authors
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

package perf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/jit"
)

type JitdumpCache struct {
	logger log.Logger

	cache *cache.LRUCacheWithTTL[string, jitdumpCacheValue]
}

type jitdumpCacheValue struct {
	m Map

	// We assume the file is unchanged if the size and modtime are the same as
	// last time we parsed it.
	fileModTime time.Time
	fileSize    int64
}

var ErrJITDumpNotFound = errors.New("jitdump not found")

func ReadJitdump(logger log.Logger, fileName string) (Map, error) {
	fd, err := os.Open(fileName)
	if err != nil {
		return Map{}, err
	}
	defer fd.Close()

	dump := &jit.JITDump{}
	err = jit.LoadJITDump(logger, fd, dump)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		if dump == nil || dump.CodeLoads == nil {
			return Map{}, err
		}
		// Some runtimes update their dump all the time (e.g. libperf_jvmti.so),
		// making it nearly impossible to read a complete file
		level.Warn(logger).Log("msg", "JIT dump file ended unexpectedly", "filename", fileName, "err", err)
	} else if err != nil {
		return Map{}, err
	}

	addrs := make([]MapAddr, 0, len(dump.CodeLoads))
	for _, cl := range dump.CodeLoads {
		addrs = append(addrs, MapAddr{cl.CodeAddr, cl.CodeAddr + cl.CodeSize, cl.Name})
	}

	// Sorted by end address to allow binary search during look-up. End to find
	// the (closest) address _before_ the end. This could be an inlined instruction
	// within a larger blob.
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].End < addrs[j].End
	})

	return Map{addrs: addrs}, nil
}

func NewJitdumpCache(logger log.Logger, reg prometheus.Registerer, profilingDuration time.Duration) *JitdumpCache {
	return &JitdumpCache{
		logger: logger,
		cache: cache.NewLRUCacheWithTTL[string, jitdumpCacheValue](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "jitdump_cache"}, reg),
			512,
			10*profilingDuration,
		),
	}
}

// DumpForPID reads the JIT dump for the given PID and filename and returns a
// Map that can be queried.
func (p *JitdumpCache) JitdumpForPID(pid int, path string) (*Map, error) {
	jitdumpFile := fmt.Sprintf("/proc/%d/root%s", pid, path)
	info, err := os.Stat(jitdumpFile)
	if os.IsNotExist(err) {
		return nil, ErrJITDumpNotFound
	}
	if err != nil {
		return nil, err
	}

	if v, ok := p.cache.Get(jitdumpFile); ok {
		if v.fileModTime == info.ModTime() && v.fileSize == info.Size() {
			return &v.m, nil
		}
		level.Debug(p.logger).Log("msg", "cached value is outdated", "pid", pid)
	}

	m, err := ReadJitdump(p.logger, jitdumpFile)
	if err != nil {
		return nil, err
	}

	p.cache.Add(jitdumpFile, jitdumpCacheValue{
		m:           m,
		fileModTime: info.ModTime(),
		fileSize:    info.Size(),
	})
	return &m, nil
}
