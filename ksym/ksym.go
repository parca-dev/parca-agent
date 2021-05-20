package ksym

import (
	"bufio"
	"errors"
	"hash"
	"hash/fnv"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	FunctionNotFoundError = errors.New("kernel function not found")
)

func newHash() hash.Hash32 {
	return fnv.New32a()
}

type KsymCache struct {
	open                  func() (io.ReadCloser, error)
	lastHash              uint32
	lastCacheInvalidation time.Time
	updateDuration        time.Duration
	fastCache             map[uint64]string
	mtx                   *sync.RWMutex
}

func NewKsymCache() *KsymCache {
	return &KsymCache{
		open:           func() (io.ReadCloser, error) { return os.Open("/proc/kallsyms") },
		fastCache:      make(map[uint64]string),
		updateDuration: time.Minute * 5,
		mtx:            &sync.RWMutex{},
	}
}

func (c *KsymCache) Resolve(addrs map[uint64]struct{}) (map[uint64]string, error) {
	c.mtx.RLock()
	lastCacheInvalidation := c.lastCacheInvalidation
	lastHash := c.lastHash
	c.mtx.RUnlock()

	if time.Now().Sub(lastCacheInvalidation) > c.updateDuration {
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
			c.mtx.Unlock()
		}
	}

	res := make(map[uint64]string, len(addrs))
	notCached := []uint64{}

	// Fast path for when we've seen this symbol before.
	c.mtx.RLock()
	for addr := range addrs {
		sym, ok := c.fastCache[addr]
		if !ok {
			notCached = append(notCached, addr)
			continue
		}
		res[addr] = sym
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

// ksym reads /proc/kallsyms and resolved the addresses to their respective
// function names. The addrs parameter must be sorted as /proc/kallsyms is
// sorted.
func (c *KsymCache) ksym(addrs []uint64) ([]string, error) {
	fd, err := c.open()
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	res := make([]string, 0, len(addrs))

	h := newHash()
	s := bufio.NewScanner(io.TeeReader(fd, h))
	lastSym := ""
	for s.Scan() {
		l := s.Text()
		ar := strings.Split(l, " ")
		if len(ar) != 3 {
			continue
		}

		curAddr, err := strconv.ParseUint(ar[0], 16, 64)
		if err != nil {
			return nil, err
		}

		for curAddr > addrs[0] { //&& curAddr >= addrs[0] {
			res = append(res, lastSym)
			addrs = addrs[1:]
			if len(addrs) == 0 {
				return res, nil
			}
		}

		lastSym = ar[2]
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

func (c *KsymCache) kallsymsHash() (uint32, error) {
	fd, err := c.open()
	if err != nil {
		return uint32(0), err
	}
	defer fd.Close()

	h := newHash()
	_, err = io.Copy(h, fd)
	if err != nil {
		return uint32(0), err
	}

	return h.Sum32(), nil
}
