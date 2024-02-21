// Copyright 2023-2024 The Parca Authors
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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/jit"
	"github.com/parca-dev/parca-agent/pkg/symtab"
)

type JITDumpCache struct {
	logger log.Logger

	cache *cache.CacheWithEvictionTTL[string, jitdumpCacheValue]

	tmpDir string
}

type jitdumpCacheValue struct {
	f *symtab.FileReader

	// We assume the file is unchanged if the size and modtime are the same as
	// last time we parsed it.
	fileModTime time.Time
	fileSize    int64
}

var ErrJITDumpNotFound = errors.New("jitdump not found")

func ReadJITdump(
	logger log.Logger,
	fileName string,
	w *symtab.FileWriter,
) (Map, error) {
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
		offset, err := w.AddString(cl.Name)
		if err != nil {
			return Map{}, fmt.Errorf("writing string: %w", err)
		}
		addrs = append(addrs, MapAddr{
			Start:        cl.CodeAddr,
			End:          cl.CodeAddr + cl.CodeSize,
			SymbolOffset: offset,
			SymbolLen:    uint16(len(cl.Name)),
		})
	}

	// Sorted by end address to allow binary search during look-up. End to find
	// the (closest) address _before_ the end. This could be an inlined instruction
	// within a larger blob.
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].End < addrs[j].End
	})

	return Map{Path: fileName, addrs: addrs}, nil
}

func NewJITDumpCache(
	logger log.Logger,
	reg prometheus.Registerer,
	tmpDir string,
	profilingDuration time.Duration,
) *JITDumpCache {
	c := &JITDumpCache{
		logger: logger,
		tmpDir: tmpDir,
	}

	f := func(key string, value jitdumpCacheValue) {
		if err := value.f.Close(); err != nil {
			level.Error(logger).Log("msg", "failed to close perf map file", "err", err)
		}

		if err := os.Remove(key); err != nil {
			level.Error(logger).Log("msg", "failed to remove perf map file", "err", err)
		}
	}

	c.cache = cache.NewLRUCacheWithEvictionTTL[string, jitdumpCacheValue](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "jitdump_cache"}, reg),
		512,
		10*profilingDuration,
		f,
	)

	return c
}

func (p *JITDumpCache) path(pid int, fileName string) string {
	return p.pathForKey(key(pid, fileName))
}

func (p *JITDumpCache) pathForKey(key string) string {
	return filepath.Join(p.tmpDir, key)
}

func key(pid int, fileName string) string {
	return filepath.Join(fmt.Sprintf("/proc/%d/root", pid), fileName)
}

// DumpForPID reads the JIT dump for the given PID and filename and returns a
// Map that can be queried.
func (p *JITDumpCache) JITDumpForPID(pid int, path string) (*symtab.FileReader, error) {
	jitdumpFile := key(pid, path)
	info, err := os.Stat(jitdumpFile)
	if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
		return nil, ErrJITDumpNotFound
	}
	if err != nil {
		return nil, err
	}

	if v, ok := p.cache.Get(jitdumpFile); ok {
		if v.fileModTime == info.ModTime() && v.fileSize == info.Size() {
			return v.f, nil
		}
		level.Debug(p.logger).Log("msg", "cached value is outdated", "pid", pid)
		if err := v.f.Close(); err != nil {
			level.Error(p.logger).Log("msg", "failed to close optimized symtab", "err", err, "pid", pid, "path", path)
		}
	}

	filePath := p.path(pid, path)
	if err := os.MkdirAll(filepath.Dir(filePath), 0o644); err != nil {
		return nil, err
	}
	f, err := optimizeAndOpenJitdump(p.logger, jitdumpFile, filePath)
	if err != nil {
		return nil, err
	}

	p.cache.Add(jitdumpFile, jitdumpCacheValue{
		f:           f,
		fileModTime: info.ModTime(),
		fileSize:    info.Size(),
	})

	return f, nil
}

func optimizeAndOpenJitdump(
	logger log.Logger,
	perfMapFile string,
	outFile string,
) (*symtab.FileReader, error) {
	w, err := symtab.NewWriter(outFile, 0)
	if err != nil {
		return nil, err
	}

	m, err := ReadJITdump(logger, perfMapFile, w)
	if err != nil {
		return nil, err
	}

	indices := m.DeduplicatedIndices()
	i := indices.Iterator()
	for i.HasNext() {
		e := m.addrs[i.Next()]
		if err := w.WriteEntry(symtab.Entry{
			Address: e.Start,
			Offset:  e.SymbolOffset,
			Len:     e.SymbolLen,
		}); err != nil {
			return nil, err
		}
	}

	if err := w.WriteHeader(); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	f, err := symtab.NewReader(outFile)
	if err != nil {
		return nil, err
	}

	return f, nil
}
