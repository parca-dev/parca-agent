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

package ksym

import (
	"bufio"
	"debug/elf"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/hash"
	"github.com/parca-dev/parca/pkg/symbol/symbolsearcher"
)

const KsymCacheSize = 10_000 // Arbitrary cache size.

type ksym struct {
	address uint64
	name    string
}

type cache struct {
	logger                log.Logger
	fs                    fs.FS
	lastHash              uint64
	lastCacheInvalidation time.Time
	updateDuration        time.Duration
	cache                 burrow.Cache
	mtx                   *sync.RWMutex
	cacheFetch            *prometheus.CounterVec
	searcher              symbolsearcher.Searcher
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

func NewKsymCache(logger log.Logger, reg prometheus.Registerer, f ...fs.FS) *cache {
	var fs fs.FS = &realfs{}
	if len(f) > 0 {
		fs = f[0]
	}
	return &cache{
		logger: logger,
		fs:     fs,
		cache: burrow.New(
			burrow.WithMaximumSize(KsymCacheSize),
		),
		updateDuration: time.Minute * 5,
		mtx:            &sync.RWMutex{},

		cacheFetch: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_ksym_cache_fetch_total",
				Help: "Hit rate for the kernel symbol cache",
			},
			[]string{"type"},
		),
	}
}

func (c *cache) Resolve(addrs map[uint64]struct{}) (map[uint64]string, error) {
	c.mtx.RLock()
	lastCacheInvalidation := c.lastCacheInvalidation
	lastHash := c.lastHash
	c.mtx.RUnlock()

	if time.Since(lastCacheInvalidation) > c.updateDuration {
		h, err := c.kallsymsHash()
		if err != nil {
			return nil, err
		}
		if h == lastHash {
			// This means the staleness interval kicked in, but the content of
			// kallsyms hasn't actually changed, so we don't need to invalidate
			// the cache.
			c.mtx.Lock()
			c.lastCacheInvalidation = time.Now()
			c.mtx.Unlock()
		} else {
			// staleness has kicked in and kallsyms has changed.
			c.mtx.Lock()
			c.lastCacheInvalidation = time.Now()
			c.lastHash = h
			c.cache = burrow.New(
				burrow.WithMaximumSize(KsymCacheSize),
			)
			err := c.loadKsyms()
			if err != nil {
				level.Debug(c.logger).Log("msg", "loadKsyms failed", "err", err)
			}
			c.mtx.Unlock()
		}
	}

	res := make(map[uint64]string, len(addrs))
	notCached := []uint64{}

	// Fast path for when we've seen this symbol before.
	c.mtx.RLock()
	for addr := range addrs {
		sym, ok := c.cache.GetIfPresent(addr)
		if !ok {
			notCached = append(notCached, addr)
			c.cacheFetch.WithLabelValues("miss").Inc()
			continue
		}
		res[addr], ok = sym.(string)
		if !ok {
			level.Error(c.logger).Log("msg", "failed to convert type from cache value to string")
		}
		c.cacheFetch.WithLabelValues("hits").Inc()
	}
	c.mtx.RUnlock()

	if len(notCached) == 0 {
		return res, nil
	}

	sort.Slice(notCached, func(i, j int) bool { return notCached[i] < notCached[j] })
	syms := c.resolveKsyms(notCached)

	for i := range notCached {
		if syms[i] != "" {
			res[notCached[i]] = syms[i]
		}
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	for i := range notCached {
		if syms[i] != "" {
			c.cache.Put(notCached[i], syms[i])
		}
	}
	return res, nil
}

// unsafeString avoids memory allocations by directly casting
// the memory area that we know contains a valid string to a
// string pointer.
func unsafeString(b []byte) string {
	return *((*string)(unsafe.Pointer(&b)))
}

// loadKsyms reads /proc/kallsyms and stores the start address for every function
// names, sorted by the start address.
func (c *cache) loadKsyms() error {
	fd, err := c.fs.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer fd.Close()

	s := bufio.NewScanner(fd)
	// My machine has ~74k loaded symbols. Reserving 50k entries, as there might be
	// boxes with fewer symbols loaded, and if we need to reallocate, we would have
	// to do it once or twice, so this value seems like a reasonable middle ground.
	//
	// For 75000 ksyms, the memory used would be roughly:
	// 75000 [number of ksyms] * (24B [size of the address and string metadata] +
	//	38 characters [P90 length symbols in my box] * 8B/character) = ~ 24600000B = ~24.6MB
	symbols := make([]elf.Symbol, 0, 50000)
	for s.Scan() {
		line := s.Bytes()

		address, err := strconv.ParseUint(unsafeString(line[:16]), 16, 64)
		if err != nil {
			level.Debug(c.logger).Log("msg", "failed to parse kallsym address")
			continue
		}

		endIndex := -1
		for i := 19; i < len(line); i++ {
			if line[i] == ' ' {
				endIndex = i
				break
			}
		}
		if endIndex == -1 {
			endIndex = len(line)
		}

		// skip module name
		name := string(line[19:endIndex])
		name = strings.TrimFunc(name, unicode.IsSpace)
		for i, c := range name {
			if unicode.IsSpace(c) {
				name = name[:i]
				break
			}
		}

		// see map__process_kallsym_symbol in util/symbol.c
		// the biggest difference between the logic here with perf kernel symbol is
		// the symbolsearcher.Searcher would only return elf.STT_FUNC symbol
		// but map__process_kallsym_symbol use symbol_type__filter to get t,w,d,b symbol
		// and the kernel symbol search function would not check symbol type
		// so the perf kernel symbol would contain elf.STT_OBJECT symbol
		symbolType := string(line[17:18])
		symbols = append(symbols, elf.Symbol{
			Name:    name,
			Info:    elf.ST_INFO(kAllSymBind(symbolType), kAllSymElfType(symbolType)),
			Other:   0,
			Section: elf.SectionIndex(1), // just to pass section check
			Value:   address,
			Size:    0,
			Version: "",
			Library: "",
		})
	}
	if err := s.Err(); err != nil {
		return s.Err()
	}
	c.searcher = symbolsearcher.New(symbols)
	return nil
}

// resolveKsyms returns the function names for the requested addresses.
func (c *cache) resolveKsyms(addrs []uint64) []string {
	result := make([]string, 0, len(addrs))

	for _, addr := range addrs {
		name, _ := c.searcher.Search(addr)
		result = append(result, name)
	}

	return result
}

func (c *cache) kallsymsHash() (uint64, error) {
	return hash.File(c.fs, "/proc/kallsyms")
}

// see kallsyms2elf_type symbol/kallsyms.c
func kAllSymElfType(s string) elf.SymType {
	s = strings.ToLower(s)
	if s == "t" || s == "w" {
		return elf.STT_FUNC
	}
	return elf.STT_OBJECT
}

// see kallsyms2elf_binding in symbol/kallsyms.c
func kAllSymBind(s string) elf.SymBind {
	if s == "W" {
		return elf.STB_WEAK
	}
	isUpper := strings.ToUpper(s) == s
	if isUpper {
		return elf.STB_GLOBAL
	}
	return elf.STB_LOCAL
}
