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
	"path/filepath"
	"sort"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/namespace"
	"github.com/parca-dev/parca-agent/pkg/symtab"
)

type PerfMapCache struct {
	logger log.Logger

	cache   *cache.CacheWithEvictionTTL[int, perfMapCacheValue]
	nsCache *namespace.Cache

	tmpDir string
}

type perfMapCacheValue struct {
	f *symtab.FileReader

	fileModTime time.Time
	fileSize    int64

	prevAddrCount   int
	prevDataLength  int
	prevStringCount int
}

var (
	ErrPerfMapNotFound = errors.New("perf-map not found")
	ErrEmptyPerfMap    = errors.New("perf-map is empty")
	ErrProcNotFound    = errors.New("process not found")
)

// TODO(kakkoyun): Add Parser type to wrap: fs and logger.

func ReadPerfMap(
	logger log.Logger,
	fileName string,
	prevAddrCount int,
	prevDataLength int,
	prevStringCount int,
) (*Map, error) {
	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	stat, err := fd.Stat()
	if err != nil {
		return nil, err
	}

	var (
		addrs []MapAddr
		st    *StringTable
	)

	if prevAddrCount > 0 {
		// If we have the previous map we use some stats to preallocate so we
		// have a good starting point.
		addrs = make([]MapAddr, 0, prevAddrCount)
		st = NewStringTable(prevDataLength, prevStringCount)
	} else {
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

		addrs = make([]MapAddr, 0, linesCount)
		st = NewStringTable(convBufSize, linesCount)
	}

	r := bufio.NewReader(fd)
	i := 0
	var multiError error
	for {
		b, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read perf map line: %w", err)
		}

		line, err := parsePerfMapLine(b, st)
		if err != nil {
			multiError = errors.Join(multiError, fmt.Errorf("parse perf map line %d: %w", i, err))
		}

		addrs = append(addrs, line)
		i++
	}

	if multiError != nil {
		level.Debug(logger).Log("msg", "some perf map lines failed to be parsed, this is somewhat expected, but this log line exists for potential troubleshooting", "err", multiError)
	}

	if len(addrs) == 0 {
		return nil, ErrEmptyPerfMap
	}

	// Sorted by end address to allow binary search during look-up. End to find
	// the (closest) address _before_ the end. This could be an inlined instruction
	// within a larger blob.
	sort.SliceStable(addrs, func(i, j int) bool {
		return addrs[i].End < addrs[j].End
	})

	return (&Map{
		Path:        fileName,
		addrs:       addrs,
		stringTable: st,
	}).Deduplicate(), nil
}

func parsePerfMapLine(b []byte, st *StringTable) (MapAddr, error) {
	firstSpace := bytes.Index(b, []byte(" "))
	if firstSpace == -1 {
		return MapAddr{}, errors.New("invalid line")
	}

	secondSpace := bytes.Index(b[firstSpace+1:], []byte(" "))
	if secondSpace == -1 {
		return MapAddr{}, errors.New("invalid line")
	}

	addrBytes := b[:firstSpace]

	// Some runtimes that produce perf maps optionally start memory
	// addresses with "0x".
	if len(addrBytes) >= 2 && addrBytes[0] == '0' && addrBytes[1] == 'x' {
		addrBytes = addrBytes[2:]
	}

	if len(b) < firstSpace+secondSpace+2 {
		return MapAddr{}, errors.New("invalid line")
	}

	sizeBytes := b[firstSpace+1 : firstSpace+1+secondSpace]
	symbolBytes := b[firstSpace+secondSpace+2:]

	start, err := parseHexToUint64(addrBytes)
	if err != nil {
		return MapAddr{}, fmt.Errorf("parsing start: %w", err)
	}
	size, err := parseHexToUint64(sizeBytes)
	if err != nil {
		return MapAddr{}, fmt.Errorf("parsing end: %w", err)
	}
	if start+size < start {
		return MapAddr{}, errors.New("overflowed mapping")
	}

	if symbolBytes[len(symbolBytes)-1] == '\n' {
		symbolBytes = symbolBytes[:len(symbolBytes)-1]
	}

	return MapAddr{
		Start:  start,
		End:    start + size,
		Symbol: st.GetOrAdd(symbolBytes),
	}, nil
}

func NewPerfMapCache(logger log.Logger, reg prometheus.Registerer, nsCache *namespace.Cache, tmpDir string, profilingDuration time.Duration) *PerfMapCache {
	c := &PerfMapCache{
		logger:  logger,
		nsCache: nsCache,
		tmpDir:  tmpDir,
	}

	f := func(key int, value perfMapCacheValue) {
		if err := value.f.Close(); err != nil {
			level.Error(logger).Log("msg", "failed to close perf map file", "err", err)
		}

		if err := os.Remove(c.path(key)); err != nil {
			level.Error(logger).Log("msg", "failed to remove perf map file", "err", err)
		}
	}

	c.cache = cache.NewLRUCacheWithEvictionTTL[int, perfMapCacheValue](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "perf_map_cache"}, reg),
		512,
		10*profilingDuration,
		f,
	)

	return c
}

func (p *PerfMapCache) path(pid int) string {
	return filepath.Join(p.tmpDir, fmt.Sprintf("perf-%d.symtab", pid))
}

// MapForPID returns the Map for the given pid if it exists.
func (p *PerfMapCache) PerfMapForPID(pid int) (*symtab.FileReader, error) {
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
	if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
		return nil, ErrPerfMapNotFound
	}
	if err != nil {
		return nil, err
	}

	v, ok := p.cache.Get(pid)
	if ok {
		if v.fileModTime == info.ModTime() && v.fileSize == info.Size() {
			return v.f, nil
		}
		level.Debug(p.logger).Log("msg", "cached value is outdated", "pid", pid)
		if err := v.f.Close(); err != nil {
			level.Error(p.logger).Log("msg", "failed to close optimized symtab", "err", err, "pid", pid)
		}
	}

	m, err := ReadPerfMap(
		p.logger,
		perfFile,
		v.prevAddrCount,
		v.prevDataLength,
		v.prevStringCount,
	)
	if err != nil {
		return nil, err
	}

	filePath := p.path(pid)
	w, err := symtab.NewWriter(filePath, len(m.addrs))
	if err != nil {
		return nil, err
	}

	for _, addr := range m.addrs {
		sym := m.stringTable.GetBytes(addr.Symbol)
		if err := w.AddSymbol(unsafeString(sym), addr.Start); err != nil {
			return nil, err
		}
	}

	if err := w.Write(); err != nil {
		return nil, err
	}

	f, err := symtab.NewReader(filePath)
	if err != nil {
		return nil, err
	}

	p.cache.Add(pid, perfMapCacheValue{
		f:           f,
		fileModTime: info.ModTime(),
		fileSize:    info.Size(),

		prevAddrCount:   len(m.addrs),
		prevDataLength:  m.stringTable.DataLength(),
		prevStringCount: m.stringTable.Len(),
	})

	return f, nil
}
