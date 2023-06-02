// Copyright 2022-2023 The Parca Authors
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

package perf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/namespace"
)

type PerfMapCache struct {
	logger log.Logger

	cache   burrow.Cache
	nsCache *namespace.Cache
}

type perfMapCacheValue struct {
	m Map

	fileModTime time.Time
	fileSize    int64
}

var (
	ErrPerfMapNotFound = errors.New("perf-map not found")
	ErrProcNotFound    = errors.New("process not found")
)

// TODO(kakkoyun): Add Parser type to wrap: fs and logger.

func ReadPerfMap(fileName string) (Map, error) {
	fd, err := os.Open(fileName)
	if err != nil {
		return Map{}, err
	}
	defer fd.Close()

	stat, err := fd.Stat()
	if err != nil {
		return Map{}, err
	}

	// Estimate the number of lines in the map file
	// and allocate a string converter when the file is sufficiently large.
	const (
		avgLineLen = 60
		avgFuncLen = 42
	)
	fileSize := stat.Size()
	linesCount := int(fileSize / avgLineLen)
	convBufSize := 0
	if linesCount > 400 {
		convBufSize = linesCount * avgFuncLen
	}

	r := bufio.NewReader(fd)
	addrs := make([]MapAddr, 0, linesCount)
	conv := newStringConverter(convBufSize)
	for {
		b, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return Map{}, err
		}

		line, err := parsePerfMapLine(b, conv)
		if err != nil {
			return Map{}, err
		}

		addrs = append(addrs, line)
	}
	// Sorted by end address to allow binary search during look-up. End to find
	// the (closest) address _before_ the end. This could be an inlined instruction
	// within a larger blob.
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].End < addrs[j].End
	})
	return Map{addrs: addrs}, nil
}

func parsePerfMapLine(b []byte, conv *stringConverter) (MapAddr, error) {
	firstSpace := bytes.Index(b, []byte(" "))
	if firstSpace == -1 {
		return MapAddr{}, fmt.Errorf("invalid line: %s", b)
	}

	secondSpace := bytes.Index(b[firstSpace+1:], []byte(" "))
	if secondSpace == -1 {
		return MapAddr{}, fmt.Errorf("invalid line: %s", b)
	}

	addrBytes := b[:firstSpace]

	// Some runtimes that produce perf maps optionally start memory
	// addresses with "0x".
	if addrBytes[0] == '0' && addrBytes[1] == 'x' {
		addrBytes = addrBytes[2:]
	}

	sizeBytes := b[firstSpace+1 : firstSpace+1+secondSpace]
	symbolBytes := b[firstSpace+secondSpace+2:]

	start, err := parseHexToUint64(addrBytes)
	if err != nil {
		return MapAddr{}, fmt.Errorf("parsing start failed on %v: %w", string(b), err)
	}
	size, err := parseHexToUint64(sizeBytes)
	if err != nil {
		return MapAddr{}, fmt.Errorf("parsing end failed on %v: %w", string(b), err)
	}
	if start+size < start {
		return MapAddr{}, fmt.Errorf("overflowed mapping: %v", string(b))
	}

	if symbolBytes[len(symbolBytes)-1] == '\n' {
		symbolBytes = symbolBytes[:len(symbolBytes)-1]
	}

	return MapAddr{
		Start:  start,
		End:    start + size,
		Symbol: conv.String(symbolBytes),
	}, nil
}

func NewPerfMapCache(logger log.Logger, reg prometheus.Registerer, nsCache *namespace.Cache, profilingDuration time.Duration) *PerfMapCache {
	return &PerfMapCache{
		logger: logger,
		cache: burrow.New(
			burrow.WithMaximumSize(512),
			burrow.WithExpireAfterAccess(10*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "perf_map_cache")),
		),
		nsCache: nsCache,
	}
}

// MapForPID returns the Map for the given pid if it exists.
func (p *PerfMapCache) PerfMapForPID(pid int) (*Map, error) {
	// NOTE(zecke): There are various limitations and things to note.
	// 1st) The input file is "tainted" and under control by the user. By all
	//      means it could be an infinitely large.

	nsPids, err := p.nsCache.Get(pid)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w when reading status", ErrProcNotFound)
		}
		return nil, err
	}
	nsPid := nsPids[len(nsPids)-1]

	perfFile := fmt.Sprintf("/proc/%d/root/tmp/perf-%d.map", pid, nsPid)
	info, err := os.Stat(perfFile)
	if os.IsNotExist(err) {
		return nil, ErrPerfMapNotFound
	}
	if err != nil {
		return nil, err
	}

	if val, ok := p.cache.GetIfPresent(pid); ok {
		v, ok := val.(perfMapCacheValue)
		if ok {
			if v.fileModTime == info.ModTime() && v.fileSize == info.Size() {
				return &v.m, nil
			}
			level.Debug(p.logger).Log("msg", "cached value is outdated", "pid", pid)
		}
		level.Warn(p.logger).Log("msg", "cached value is not a cacheValue", "pid", pid)
	}

	m, err := ReadPerfMap(perfFile)
	if err != nil {
		return nil, err
	}

	p.cache.Put(pid, perfMapCacheValue{
		m:           m,
		fileModTime: info.ModTime(),
		fileSize:    info.Size(),
	})
	return &m, nil
}
