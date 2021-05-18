package ksym

import (
	"bufio"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	FunctionNotFoundError              = errors.New("kernel function not found")
	castagnoliTable       *crc32.Table = crc32.MakeTable(crc32.Castagnoli)
)

func newCRC32() hash.Hash32 {
	return crc32.New(castagnoliTable)
}

type Symbol struct {
	Addr uint64
	Type string
	Name string
}

type KsymCache struct {
	lastHash       uint32
	lastUpdated    time.Time
	updateDuration time.Duration
	ksyms          []Symbol
	fastCache      map[uint64]Symbol
	mtx            *sync.RWMutex
}

var cache KsymCache = KsymCache{
	fastCache:      make(map[uint64]Symbol),
	updateDuration: time.Minute * 5,
	mtx:            &sync.RWMutex{},
}

func Resolve(addr uint64) (Symbol, error) {
	return cache.Resolve(addr)
}

func (c *KsymCache) Resolve(addr uint64) (Symbol, error) {
	c.mtx.RLock()
	lastUpdated := c.lastUpdated
	c.mtx.RUnlock()

	if time.Now().Sub(lastUpdated) > c.updateDuration {
		needsUpdate, err := c.needsUpdate()
		if err != nil {
			return Symbol{}, err
		}
		if needsUpdate {
			err := c.update()
			if err != nil {
				return Symbol{}, err
			}
		}
		// This means the staleness interval kicked in, but the content didn't
		// actually change so we don't need to update the cache.
		c.mtx.Lock()
		c.lastUpdated = time.Now()
		c.mtx.Unlock()
	}

	// Fast path for when we've seen this symbol before.
	c.mtx.RLock()
	if sym, ok := c.fastCache[addr]; ok {
		c.mtx.RUnlock()
		return sym, nil
	}
	c.mtx.RUnlock()

	fn, err := c.ksym(addr)
	if err != nil {
		return Symbol{}, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Slow path, but in case it was recently written we don't need to do an
	// unnecessary write.
	if sym, ok := c.fastCache[addr]; ok {
		return sym, nil
	}

	c.fastCache[addr] = fn
	return fn, nil
}

func (c *KsymCache) ksym(addr uint64) (Symbol, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	i := sort.Search(len(c.ksyms), func(i int) bool { return c.ksyms[i].Addr >= addr })
	if i == -1 || i >= len(c.ksyms) {
		return Symbol{}, FunctionNotFoundError
	}

	return c.ksyms[i], nil
}

func (c *KsymCache) update() error {
	fd, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer fd.Close()

	c.mtx.RLock()
	ksyms := make([]Symbol, 0, len(c.ksyms))
	c.mtx.RUnlock()

	h := newCRC32()
	s := bufio.NewScanner(io.TeeReader(fd, h))
	for s.Scan() {
		l := s.Text()
		ar := strings.Split(l, " ")
		if len(ar) != 3 {
			continue
		}

		addr, err := strconv.ParseUint(ar[0], 16, 64)
		if err != nil {
			return err
		}

		ksyms = append(ksyms, Symbol{
			Addr: addr,
			Type: ar[1],
			Name: ar[2],
		})
	}
	if err := s.Err(); err != nil {
		return s.Err()
	}

	c.mtx.Lock()
	if time.Now().Sub(c.lastUpdated) > c.updateDuration {
		c.lastHash = h.Sum32()
		c.ksyms = ksyms
		c.lastUpdated = time.Now()
		c.fastCache = map[uint64]Symbol{}
	}
	c.mtx.Unlock()

	return nil
}

func (c *KsymCache) needsUpdate() (bool, error) {
	fd, err := os.Open("/proc/kallsyms")
	if err != nil {
		return false, err
	}
	defer fd.Close()

	h := newCRC32()
	_, err = io.Copy(h, fd)
	if err != nil {
		return false, err
	}

	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return h.Sum32() != c.lastHash, nil
}
