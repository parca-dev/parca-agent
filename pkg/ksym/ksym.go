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
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/parca-dev/parca-agent/pkg/hash"
)

type Ksym struct {
	logger                log.Logger
	tempDir               string
	fs                    fs.FS
	lastHash              uint64
	lastCacheInvalidation time.Time
	updateDuration        time.Duration
	mtx                   *sync.RWMutex
	optimizedReader       *fileReader
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

func NewKsym(logger log.Logger, reg prometheus.Registerer, tempDir string, f ...fs.FS) *Ksym {
	var fs fs.FS = &realfs{}
	if len(f) > 0 {
		fs = f[0]
	}
	return &Ksym{
		logger:         logger,
		tempDir:        tempDir,
		fs:             fs,
		updateDuration: time.Minute * 5,
		mtx:            &sync.RWMutex{},
	}
}

func (c *Ksym) Resolve(addrs map[uint64]struct{}) (map[uint64]string, error) {
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
			err = c.reload()
			if err != nil {
				level.Error(c.logger).Log("msg", "reloading optimized kernel symbolizer failed", "err", err)
			}
			c.mtx.Unlock()
		}
	}

	res := make(map[uint64]string, len(addrs))
	toResolve := []uint64{}

	for addr := range addrs {
		toResolve = append(toResolve, addr)
	}

	if len(toResolve) == 0 {
		return res, nil
	}

	syms := c.resolveKsyms(toResolve)

	for i := range toResolve {
		if syms[i] != "" {
			res[toResolve[i]] = syms[i]
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

func (c *Ksym) reload() error {
	path := path.Join(c.tempDir, "parca-agent-kernel-symbols")

	// Generate optimized file.
	writer, err := NewWriter(path, 100)
	if err != nil {
		return fmt.Errorf("newWriter: %w", err)
	}

	err = c.loadKsyms(
		func(addr uint64, symbol string) {
			_ = writer.addSymbol(symbol, addr)
		},
	)
	if err != nil {
		return fmt.Errorf("loadKsyms: %w", err)
	}

	err = writer.Write()
	if err != nil {
		return fmt.Errorf("writer.Write: %w", err)
	}

	// Set up reader.
	reader, err := NewReader(path)
	if err != nil {
		return fmt.Errorf("newReader: %w", err)
	}
	c.optimizedReader = reader
	return nil
}

// loadKsyms reads /proc/kallsyms and passed the address and symbol name
// to the given callback.
func (c *Ksym) loadKsyms(callback func(uint64, string)) error {
	fd, err := c.fs.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer fd.Close()

	s := bufio.NewScanner(fd)

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

		symbol := string(line[19:endIndex])
		callback(address, symbol)
	}
	if err := s.Err(); err != nil {
		return s.Err()
	}

	return nil
}

// resolveKsyms returns the function names for the requested addresses.
func (c *Ksym) resolveKsyms(addrs []uint64) []string {
	result := make([]string, 0, len(addrs))

	for _, addr := range addrs {
		symbol, err := c.optimizedReader.symbolize(addr)
		if err != nil {
			result = append(result, "")
		} else {
			result = append(result, symbol)
		}
	}

	return result
}

func (c *Ksym) kallsymsHash() (uint64, error) {
	return hash.File(c.fs, "/proc/kallsyms")
}
