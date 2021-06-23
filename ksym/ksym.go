package ksym

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/parca-dev/parca-agent/hash"
)

var (
	FunctionNotFoundError = errors.New("kernel function not found")
)

type KsymCache struct {
	logger                log.Logger
	fs                    fs.FS
	lastHash              uint64
	lastCacheInvalidation time.Time
	updateDuration        time.Duration
	fastCache             map[uint64]string
	mtx                   *sync.RWMutex
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) { return os.Open(name) }

func NewKsymCache(logger log.Logger) *KsymCache {
	return &KsymCache{
		logger:         logger,
		fs:             &realfs{},
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

func unsafeString(b []byte) string {
	return *((*string)(unsafe.Pointer(&b)))
}

// ksym reads /proc/kallsyms and resolved the addresses to their respective
// function names. The addrs parameter must be sorted as /proc/kallsyms is
// sorted.
func (c *KsymCache) ksym(addrs []uint64) ([]string, error) {
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

func (c *KsymCache) kallsymsHash() (uint64, error) {
	return hash.File(c.fs, "/proc/kallsyms")
}
