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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/hash"
	"github.com/parca-dev/parca-agent/pkg/jit"
)

type cache struct {
	fs     fs.FS
	logger log.Logger
	// TODO(kakkoyun): Convert to LRU cache.
	// - These maps are unbounded and never cleaned up.
	cache      map[int]*Map
	pidMapHash map[int]uint64
	nsPID      map[int]int
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
	ErrPerfMapNotFound = errors.New("perf-map not found")
	ErrProcNotFound    = errors.New("process not found")
	ErrNoSymbolFound   = errors.New("no symbol found")
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

func MapFromDump(logger log.Logger, fs fs.FS, fileName string) (Map, error) {
	fd, err := fs.Open(fileName)
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

func (p *Map) Lookup(addr uint64) (string, error) {
	idx := sort.Search(len(p.addrs), func(i int) bool {
		return addr < p.addrs[i].End
	})
	if idx == len(p.addrs) || p.addrs[idx].Start > addr {
		return "", ErrNoSymbolFound
	}

	return p.addrs[idx].Symbol, nil
}

func NewCache(logger log.Logger) *cache {
	return &cache{
		fs:         &realfs{},
		logger:     logger,
		cache:      map[int]*Map{},
		nsPID:      map[int]int{},
		pidMapHash: map[int]uint64{},
	}
}

// MapForPID returns the Map for the given pid if it exists.
func (p *cache) MapForPID(pid int) (*Map, error) {
	// NOTE(zecke): There are various limitations and things to note.
	// 1st) The input file is "tainted" and under control by the user. By all
	//      means it could be an infinitely large.

	nsPid, found := p.nsPID[pid]
	if !found {
		nsPids, err := FindNSPIDs(p.fs, pid)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w when reading status", ErrProcNotFound)
			}
			return nil, err
		}

		p.nsPID[pid] = nsPids[len(nsPids)-1]
		nsPid = p.nsPID[pid]
	}

	perfFile := fmt.Sprintf("/proc/%d/root/tmp/perf-%d.map", pid, nsPid)
	h, err := hash.File(p.fs, perfFile)
	if os.IsNotExist(err) {
		perfFile, err = findJITDump(pid, nsPid)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w when searching for JITDUMP", ErrProcNotFound)
			}
			return nil, err
		}
		h, err = hash.File(p.fs, perfFile)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrPerfMapNotFound
			}
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	if p.pidMapHash[pid] == h {
		return p.cache[pid], nil
	}

	var m Map
	switch {
	case strings.HasSuffix(perfFile, ".map"):
		m, err = ReadMap(p.fs, perfFile)
	case strings.HasSuffix(perfFile, ".dump"):
		m, err = MapFromDump(p.logger, p.fs, perfFile)
	default:
		// should never happen
		return nil, ErrPerfMapNotFound
	}
	if err != nil {
		return nil, err
	}

	p.cache[pid] = &m
	p.pidMapHash[pid] = h // TODO(zecke): Resolve time of check/time of use.
	return &m, nil
}

func FindNSPIDs(fs fs.FS, pid int) ([]int, error) {
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

func extractPIDsFromLine(line string) ([]int, error) {
	trimmedLine := strings.TrimPrefix(line, "NSpid:")
	pidStrings := strings.Fields(trimmedLine)

	pids := make([]int, 0, len(pidStrings))
	for _, pidStr := range pidStrings {
		pid, err := strconv.ParseInt(pidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parsing pid failed on %v: %w", pidStr, err)
		}

		pids = append(pids, int(pid))
	}

	return pids, nil
}

func findJITDump(pid, nsPid int) (string, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return "", fmt.Errorf("failed to instantiate process: %w", err)
	}

	procMaps, err := proc.ProcMaps()
	if err != nil {
		return "", fmt.Errorf("failed to read process maps: %w", err)
	}

	jitDumpName := fmt.Sprintf("/jit-%d.dump", nsPid)
	for _, m := range procMaps {
		if strings.HasSuffix(m.Pathname, jitDumpName) {
			return fmt.Sprintf("/proc/%d/root%s", pid, m.Pathname), nil
		}
	}

	return "", ErrPerfMapNotFound
}
