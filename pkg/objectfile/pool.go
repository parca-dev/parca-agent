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

package objectfile

import (
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/atomic"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/cache"
)

type Cache[K comparable, V any] interface {
	Add(K, V)
	Get(K) (V, bool)
	Peek(K) (V, bool)
	Remove(K)
	Purge()
}

const (
	lvSuccess = "success"
	lvError   = "error"
	lvShared  = "shared"

	lvNotFound    = "not_found"
	lvNotELF      = "not_elf"
	lvOpenUnknown = "open_unknown"
	lvBuildID     = "build_id"
	lvRewind      = "rewind"
	lvStat        = "stat"
)

type metrics struct {
	opened           *prometheus.CounterVec
	openErrors       *prometheus.CounterVec
	open             prometheus.Gauge
	closeAttempts    prometheus.Counter
	closed           *prometheus.CounterVec
	keptOpenDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		opened: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_objectfile_opened_total",
			Help: "Total number of object file attempts to open.",
		}, []string{"result"}),
		openErrors: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_objectfile_open_errors_total",
			Help: "Total number of object file open errors.",
		}, []string{"type"}),
		open: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "parca_agent_objectfile_open",
			Help: "Total number of object files open.",
		}),
		closeAttempts: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_objectfile_close_attempts_total",
			Help: "Total number of object file attempts to close.",
		}),
		closed: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_objectfile_closed_total",
			Help: "Total number of object file close operations.",
		}, []string{"result"}),
		keptOpenDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:                        "parca_agent_objectfile_kept_open_duration_seconds",
			Help:                        "Duration of object files kept open.",
			NativeHistogramBucketFactor: 1.1,
		}),
	}
	m.opened.WithLabelValues(lvSuccess)
	m.opened.WithLabelValues(lvError)
	m.opened.WithLabelValues(lvShared)
	m.openErrors.WithLabelValues(lvNotFound)
	m.openErrors.WithLabelValues(lvNotELF)
	m.openErrors.WithLabelValues(lvOpenUnknown)
	m.openErrors.WithLabelValues(lvBuildID)
	m.openErrors.WithLabelValues(lvRewind)
	m.openErrors.WithLabelValues(lvStat)
	m.closed.WithLabelValues(lvSuccess)
	m.closed.WithLabelValues(lvError)
	return m
}

type cacheKey struct {
	// Possible paths:
	// - (for extracted debuginfo) /tmp/<buildid>
	// - (for found debuginfo) /usr/lib/debug/.build-id/<2-char>/<buildid>.debug
	// - (for running processes) /proc/123/root/usr/bin/parca-agent
	// - (for shared libraries) /proc/123/root/usr/lib/libc.so.6
	// - (for singleton objects) /usr/lib/modules/5.4.0-65-generic/vdso/vdso64.so
	path    string
	buildID string
	modtime time.Time
}

type Pool struct {
	logger  log.Logger
	metrics *metrics

	// There could be multiple object files mapped to different processes.
	keyCache Cache[string, cacheKey]
	objCache Cache[cacheKey, *ObjectFile]
}

const keepAliveProfileCycle = 18

func NewPool(logger log.Logger, reg prometheus.Registerer, poolSize int, profilingDuration time.Duration) *Pool {
	p := &Pool{
		logger:  logger,
		metrics: newMetrics(reg),
		// NOTICE: The behavior is now different than the previous implementation.
		// - The previous implementation was using a ExpireAfterAccess strategy, now it is behaves like ExpireAfterWrite strategy.
		// - This could be better it just needs to be noted.
		keyCache: cache.NewLRUCacheWithTTL[string, cacheKey](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "objectfile_key"}, reg),
			poolSize,
			keepAliveProfileCycle*profilingDuration,
		),
	}

	p.objCache = cache.NewLRUCacheWithEvictionTTL[cacheKey, *ObjectFile](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "objectfile"}, reg),
		poolSize,
		keepAliveProfileCycle*profilingDuration,
		p.onEvicted,
	)
	return p
}

func (p *Pool) onEvicted(k cacheKey, obj *ObjectFile) {
	level.Debug(p.logger).Log("msg", "evicting object file", "key", fmt.Sprintf("%+v", k))
	if err := obj.close(); err != nil {
		level.Debug(p.logger).Log("msg", "failed to close object file when evicted", "err", err)
	}
}

func (p *Pool) get(key cacheKey) (*ObjectFile, error) {
	if obj, ok := p.objCache.Get(key); ok {
		p.metrics.opened.WithLabelValues(lvShared).Inc()
		return obj, nil
	}
	return nil, fmt.Errorf("no reference found for %s", key.path)
}

// Open opens the specified executable or library file from the given path.
// And creates a new ObjectFile reference.
// The returned reference should be released after use.
// The file will be closed when the reference is released.
func (p *Pool) Open(path string) (*ObjectFile, error) {
	if key, ok := p.keyCache.Get(path); ok {
		if obj, err := p.get(key); err == nil {
			return obj, nil
		}
		// There is liveness difference between two caches, so we need to remove the key from the keyCache,
		// if it is NOT found in the objCache.
		p.keyCache.Remove(path)
	}

	f, err := os.Open(path)
	if err != nil {
		p.metrics.opened.WithLabelValues(lvError).Inc()
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			p.metrics.openErrors.WithLabelValues(lvNotFound).Inc()
		}
		return nil, fmt.Errorf("error opening %s: %w", path, err)
	}

	key, err := cacheKeyFromFile(f)
	if err == nil {
		if obj, err := p.get(key); err == nil {
			// We could end up here:
			// - if the executable file was opened by another process (this includes restarts).
			// - if the executable file linked to a shared library that was opened by another process.
			// - if a singleton object was opened by another process and requested again.
			// - if a debuginfo extracted from the same source objectfile (if happens it's a race condition).
			p.keyCache.Add(path, key)
			return obj, nil
		}
	}
	return p.NewFile(f)
}

//nolint:unused
var (
	// Has a closer and keeps a reference to the file.
	elfOpen = elf.Open
	// Doesn't have a closer and doesn't keep a reference to the file.
	elfNewFile = elf.NewFile
)

// NewFile creates a new ObjectFile reference from an existing file.
// The returned reference should be released after use.
// The file will be closed when the reference is released.
func (p *Pool) NewFile(f *os.File) (_ *ObjectFile, err error) { //nolint:nonamedreturns
	defer func() {
		if err != nil {
			p.metrics.opened.WithLabelValues(lvError).Inc()
			return
		}
	}()

	closer := func(err error) error {
		if cErr := f.Close(); cErr != nil {
			err = errors.Join(err, cErr)
		}
		return err
	}

	path := f.Name()
	// > Clients of ReadAt can execute parallel ReadAt calls on the same input source.
	ef, err := elfNewFile(f)
	if err != nil {
		var elfErr *elf.FormatError
		if errors.As(err, &elfErr) {
			p.metrics.openErrors.WithLabelValues(lvNotELF).Inc()
		} else {
			p.metrics.openErrors.WithLabelValues(lvOpenUnknown).Inc()
		}
		return nil, closer(fmt.Errorf("error opening %s: %w", path, err))
	}
	if len(ef.Sections) == 0 {
		return nil, closer(errors.New("ELF does not have any sections"))
	}

	buildID, err := buildid.FromELF(ef)
	if err != nil {
		p.metrics.openErrors.WithLabelValues(lvBuildID).Inc()
		return nil, closer(fmt.Errorf("failed to get build ID from ELF for %s: %w", path, err))
	}
	if rErr := rewind(f); rErr != nil {
		p.metrics.openErrors.WithLabelValues(lvRewind).Inc()
		return nil, closer(rErr)
	}

	stat, err := f.Stat()
	if err != nil {
		p.metrics.openErrors.WithLabelValues(lvStat).Inc()
		return nil, fmt.Errorf("failed to get stats of the file: %w", err)
	}

	key := cacheKey{
		path:    removeProcPrefix(path),
		buildID: buildID,
		modtime: stat.ModTime(),
	}
	if val, ok := p.objCache.Get(key); ok {
		// A file for this buildID is already in the cache, so close the file we just opened.
		// The existing file could be already closed, because we are done uploading it.
		// It's the callers responsibility to making sure the file is still open.
		if err := closer(nil); err != nil {
			return nil, err
		}
		p.metrics.opened.WithLabelValues(lvShared).Inc()
		return val, nil
	}

	obj := &ObjectFile{
		p: p,

		BuildID: buildID,
		Path:    path,

		file:     f,
		openedAt: time.Now(),
		Size:     stat.Size(),
		Modtime:  stat.ModTime(),
		closed:   atomic.NewBool(false),
		elf:      ef,
	}
	p.metrics.opened.WithLabelValues(lvSuccess).Inc()
	p.metrics.open.Inc()

	key = cacheKeyFromObject(obj)
	p.keyCache.Add(path, key)
	p.objCache.Add(key, obj)
	return obj, nil
}

// Close closes the pool and all the files in it.
func (p *Pool) Close() error {
	// Remove all the cached files from the pool.
	p.keyCache.Purge()
	p.objCache.Purge()
	return nil
}

var rgx = regexp.MustCompile(`^/proc/\d+/root`)

func removeProcPrefix(path string) string {
	return rgx.ReplaceAllString(path, "")
}

func cacheKeyFromObject(obj *ObjectFile) cacheKey {
	return cacheKey{
		path:    removeProcPrefix(obj.Path),
		buildID: obj.BuildID,
		modtime: obj.Modtime,
	}
}

func cacheKeyFromFile(f *os.File) (cacheKey, error) {
	path := f.Name()
	stat, err := f.Stat()
	if err != nil {
		return cacheKey{}, fmt.Errorf("failed to get stats of the file: %w", err)
	}
	// This a fast path to extract the buildID from the ELF header.
	// It only reads first 32kb of the file.
	// If the buildID is not found, we fall back to the slower path.
	// This will be useful for the case where the buildID is already in the cache.
	buildID, err := buildid.FromFile(f)
	if err != nil {
		return cacheKey{}, fmt.Errorf("cacheKeyFromFile: failed to get build ID for %s: %w", path, err)
	}
	return cacheKey{
		path:    removeProcPrefix(path),
		buildID: buildID,
		modtime: stat.ModTime(),
	}, nil
}
