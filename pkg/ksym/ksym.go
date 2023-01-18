// Copyright 2022 The Parca Authors
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
	"io/fs"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/hash"
)

const KsymCacheSize = 10_000 // Arbitrary cache size.

type ksym struct {
	address uint64
	name    string
}

type cache struct {
	logger                log.Logger
	fs                    fs.FS
	kernelSymbols         []ksym
	lastHash              uint64
	lastCacheInvalidation time.Time
	updateDuration        time.Duration
	cache                 burrow.Cache
	mtx                   *sync.RWMutex
	cacheFetch            *prometheus.CounterVec
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
		// My machine has ~74k loaded symbols. Reserving 50k entries, as there might be
		// boxes with fewer symbols loaded, and if we need to reallocate, we would have
		// to do it once or twice, so this value seems like a reasonable middle ground.
		//
		// For 75000 ksyms, the memory used would be roughly:
		// 75000 [number of ksyms] * (24B [size of the address and string metadata] +
		//	38 characters [P90 length symbols in my box] * 8B/character) = ~ 24600000B = ~24.6MB
		kernelSymbols: make([]ksym, 0, 50000),
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
	symbol := ""

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

		// We care about symbols that are either in the:
		// - T, t, as they live in the .text (code) section.
		// - A, means that the symbol value is absolute.
		//
		// Add this denylist for symbols that live in the (b)ss section
		// (d) unitialised data section and (r)ead only data section, in
		// case there are valid symbols types that we aren't adding.
		//
		// See https://linux.die.net/man/1/nm.
		symbolType := string(line[17:18])
		if symbolType == "b" || symbolType == "B" || symbolType == "d" ||
			symbolType == "D" || symbolType == "r" || symbolType == "R" {
			continue
		}

		symbol = string(line[19:endIndex])
		c.kernelSymbols = append(c.kernelSymbols, ksym{address: address, name: symbol})
	}
	if err := s.Err(); err != nil {
		return s.Err()
	}

	// Sort the kernel symbols, as we will binary search over them.
	sort.Slice(c.kernelSymbols, func(i, j int) bool { return c.kernelSymbols[i].address < c.kernelSymbols[j].address })
	return nil
}

// resolveKsyms returns the function names for the requested addresses.
func (c *cache) resolveKsyms(addrs []uint64) []string {
	result := make([]string, 0, len(addrs))

	for _, addr := range addrs {
		idx := sort.Search(len(c.kernelSymbols), func(i int) bool { return addr < c.kernelSymbols[i].address })
		if idx < len(c.kernelSymbols) && idx > 0 {
			result = append(result, c.kernelSymbols[idx-1].name)
		} else {
			result = append(result, "")
		}
	}

	return result
}

func (c *cache) kallsymsHash() (uint64, error) {
	return hash.File(c.fs, "/proc/kallsyms")
}
