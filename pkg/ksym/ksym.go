// Copyright 2021 The Parca Authors
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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/parca-dev/parca-agent/pkg/hash"
)

var ErrFunctionNotFound = errors.New("kernel function not found")

type CacheStats struct {
	Hits  int
	Total int
}

type Cache struct {
	logger                log.Logger
	fs                    fs.FS
	lastHash              uint64
	lastCacheInvalidation time.Time
	updateDuration        time.Duration
	fastCache             map[uint64]string
	Stats                 CacheStats
	mtx                   *sync.RWMutex
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

func (c CacheStats) HitRate() float64 {
	return 100 * float64(c.Hits) / float64(c.Total)
}

func (c CacheStats) String() string {
	return fmt.Sprintf("Ksym hit rate: %.2f%% (%d Total cache accesses)", c.HitRate(), c.Total)
}

func NewKsymCache(logger log.Logger) *Cache {
	return &Cache{
		logger:         logger,
		fs:             &realfs{},
		fastCache:      make(map[uint64]string),
		updateDuration: time.Minute * 5,
		Stats:          CacheStats{Hits: 0, Total: 0},
		mtx:            &sync.RWMutex{},
	}
}

// TODO(kakkoyun): https://github.com/aquasecurity/libbpfgo/blob/main/helpers/kernel_symbols.go
func (c *Cache) Resolve(addrs map[uint64]struct{}) (map[uint64]string, error) {
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
			// kallsyms hasn't actually changed so we don't need to invalidate
			// the cache.
			c.mtx.Lock()
			c.lastCacheInvalidation = time.Now()
			c.mtx.Unlock()
		} else {
			// staleness has kicked in and kallsyms has changed.
			c.mtx.Lock()
			c.lastCacheInvalidation = time.Now()
			c.lastHash = h
			c.fastCache = map[uint64]string{}
			c.Stats = CacheStats{Hits: 0, Total: 0}
			c.mtx.Unlock()
		}
	}

	res := make(map[uint64]string, len(addrs))
	notCached := []uint64{}

	// Fast path for when we've seen this symbol before.
	c.mtx.RLock()
	for addr := range addrs {
		sym, ok := c.fastCache[addr]
		c.Stats.Total += 1

		if !ok {
			notCached = append(notCached, addr)
			continue
		}
		res[addr] = sym
		c.Stats.Hits += 1
	}
	c.mtx.RUnlock()

	if len(notCached) == 0 {
		return res, nil
	}

	sort.Slice(notCached, func(i, j int) bool { return notCached[i] < notCached[j] })
	syms, err := c.ksym(notCached)
	if err != nil {
		return nil, err
	}

	for i := range notCached {
		if syms[i] != "" {
			res[notCached[i]] = syms[i]
		}
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	for i := range notCached {
		if syms[i] != "" {
			c.fastCache[notCached[i]] = syms[i]
		}
	}
	return res, nil
}

func unsafeString(b []byte) string {
	return *((*string)(unsafe.Pointer(&b)))
}

// ksym reads /proc/kallsyms and resolved the addresses to their respective
// function names. The addrs parameter must be sorted as /proc/kallsyms is
// sorted.
func (c *Cache) ksym(addrs []uint64) ([]string, error) {
	fd, err := c.fs.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	res := make([]string, 0, len(addrs))

	s := bufio.NewScanner(fd)
	lastSym := ""

	for s.Scan() {
		l := s.Bytes()

		curAddr, err := strconv.ParseUint(unsafeString(l[:16]), 16, 64)
		if err != nil {
			level.Warn(c.logger).Log("msg", "failed to parse kallsym address")
			continue
		}

		for curAddr > addrs[0] {
			res = append(res, lastSym)
			addrs = addrs[1:]
			if len(addrs) == 0 {
				return res, nil
			}
		}

		endIndex := -1
		for i := 19; i < len(l); i++ {
			// 0x20 is " " (space).
			if l[i] == 0x20 {
				endIndex = i
				break
			}
		}
		if endIndex == -1 {
			endIndex = len(l)
		}

		lastSym = string(l[19:endIndex])
	}
	if err := s.Err(); err != nil {
		return nil, s.Err()
	}

	for range addrs {
		// Couldn't find symbols for these address spaces.
		res = append(res, "")
	}

	return res, nil
}

func (c *Cache) kallsymsHash() (uint64, error) {
	return hash.File(c.fs, "/proc/kallsyms")
}
