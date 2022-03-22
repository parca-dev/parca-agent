// Copyright (c) 2022 The Parca Authors
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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/go-kit/log"

	"github.com/parca-dev/parca-agent/pkg/hash"
)

type Cache struct {
	fs         fs.FS
	logger     log.Logger
	cache      map[uint32]*Map
	pidMapHash map[uint32]uint64
	nsPID      map[uint32]uint32
}

type MapAddr struct {
	Start  uint64
	End    uint64
	Symbol string
}

type Map struct {
	addrs []MapAddr
}

type realfs struct{}

var (
	ErrNotFound      = errors.New("not found")
	ErrNoSymbolFound = errors.New("no symbol found")
)

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func ReadMap(fs fs.FS, fileName string) (Map, error) {
	fd, err := fs.Open(fileName)
	if err != nil {
		return Map{}, err
	}
	defer fd.Close()

	s := bufio.NewScanner(fd)
	addrs := make([]MapAddr, 0)
	for s.Scan() {
		l := strings.SplitN(s.Text(), " ", 3)
		if len(l) < 3 {
			return Map{}, fmt.Errorf("splitting failed: %v", l)
		}

		// Some runtimes that produce perf maps optionally start memory
		// addresses with "0x".
		start, err := strconv.ParseUint(strings.TrimPrefix(l[0], "0x"), 16, 64)
		if err != nil {
			return Map{}, fmt.Errorf("parsing start failed on %v: %w", l, err)
		}
		size, err := strconv.ParseUint(l[1], 16, 64)
		if err != nil {
			return Map{}, fmt.Errorf("parsing end failed on %v: %w", l, err)
		}
		if start+size < start {
			return Map{}, fmt.Errorf("overflowed mapping: %v", l)
		}
		addrs = append(addrs, MapAddr{start, start + size, l[2]})
	}
	// Sorted by end address to allow binary search during look-up. End to find
	// the (closest) address _before_ the end. This could be an inlined instruction
	// within a larger blob.
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].End < addrs[j].End
	})
	return Map{addrs: addrs}, s.Err()
}

func (p *Map) Lookup(addr uint64) (string, error) {
	idx := sort.Search(len(p.addrs), func(i int) bool {
		return addr < p.addrs[i].End
	})
	if idx == len(p.addrs) || p.addrs[idx].Start > addr {
		return "", ErrNoSymbolFound
	}

	return p.addrs[idx].Symbol, nil
}

func NewPerfCache(logger log.Logger) *Cache {
	return &Cache{
		fs:         &realfs{},
		logger:     logger,
		cache:      map[uint32]*Map{},
		nsPID:      map[uint32]uint32{},
		pidMapHash: map[uint32]uint64{},
	}
}

// CacheForPID returns the Map for the given pid if it exists.
func (p *Cache) CacheForPID(pid uint32) (*Map, error) {
	// NOTE(zecke): There are various limitations and things to note.
	// 1st) The input file is "tainted" and under control by the user. By all
	//      means it could be an infinitely large.

	nsPid, found := p.nsPID[pid]
	if !found {
		nsPids, err := findNSPIDs(p.fs, pid)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrNotFound
			}
			return nil, err
		}

		p.nsPID[pid] = nsPids[len(nsPids)-1]
		nsPid = p.nsPID[pid]
	}

	perfFile := fmt.Sprintf("/proc/%d/root/tmp/perf-%d.map", pid, nsPid)
	h, err := hash.File(p.fs, perfFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if p.pidMapHash[pid] == h {
		return p.cache[pid], nil
	}

	m, err := ReadMap(p.fs, perfFile)
	if err != nil {
		return nil, err
	}

	p.cache[pid] = &m
	p.pidMapHash[pid] = h // TODO(zecke): Resolve time of check/time of use.
	return &m, nil
}

func findNSPIDs(fs fs.FS, pid uint32) ([]uint32, error) {
	f, err := fs.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	found := false
	line := ""
	for scanner.Scan() {
		line = scanner.Text()
		if strings.HasPrefix(line, "NSpid:") {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("no NSpid line found in /proc/%d/status", pid)
	}

	return extractPIDsFromLine(line)
}

func extractPIDsFromLine(line string) ([]uint32, error) {
	trimmedLine := strings.TrimPrefix(line, "NSpid:")
	pidStrings := strings.Fields(trimmedLine)

	pids := make([]uint32, 0, len(pidStrings))
	for _, pidStr := range pidStrings {
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parsing pid failed on %v: %w", pidStr, err)
		}

		res := uint32(pid)
		pids = append(pids, res)
	}

	return pids, nil
}
