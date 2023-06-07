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
	"runtime"
	"sync"
	"time"

	"github.com/go-kit/log"
	burrow "github.com/goburrow/cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/cache"
)

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
	openReaders      prometheus.Gauge
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
		openReaders: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "parca_agent_objectfile_open_readers",
			Help: "Total number of open readers.",
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

type Pool struct {
	metrics *metrics
	// A map of path to buildID.
	buildIDCache burrow.Cache
	// A map of buildID to ObjectFile.
	objCache burrow.Cache
	// There could be multiple object files mapped to different processes.
}

const keepAliveProfileCycle = 30

func NewPool(logger log.Logger, reg prometheus.Registerer, profilingDuration time.Duration) *Pool {
	return &Pool{
		metrics: newMetrics(reg),
		buildIDCache: burrow.New(
			burrow.WithExpireAfterAccess(keepAliveProfileCycle*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "buildid")),
		),
		objCache: burrow.New(
			burrow.WithExpireAfterAccess(keepAliveProfileCycle*profilingDuration),
			burrow.WithStatsCounter(cache.NewBurrowStatsCounter(logger, reg, "objectfile")),
		),
	}
}

func (p *Pool) get(buildID string) (*ObjectFile, error) {
	if val, ok := p.objCache.GetIfPresent(buildID); ok {
		val, ok := val.(ObjectFile)
		if !ok {
			return nil, fmt.Errorf("unexpected type in cache: %T", val)
		}

		p.metrics.opened.WithLabelValues(lvShared).Inc()
		return &val, nil
	}

	return nil, fmt.Errorf("no reference found for buildid %s", buildID)
}

// Open opens the specified executable or library file from the given path.
// And creates a new ObjectFile reference.
// The returned reference should be released after use.
// The file will be closed when the reference is released.
func (p *Pool) Open(path string) (*ObjectFile, error) {
	if val, ok := p.buildIDCache.GetIfPresent(path); ok {
		buildID, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected type in cache: %T", val)
		}

		return p.get(buildID)
	}

	f, err := os.Open(path)
	if err != nil {
		p.metrics.opened.WithLabelValues(lvError).Inc()
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			p.metrics.openErrors.WithLabelValues(lvNotFound).Inc()
		}
		return nil, fmt.Errorf("error opening %s: %w", path, err)
	}

	// This a fast path to extract the buildID from the ELF header.
	// It only reads first 32kb of the file.
	// If the buildID is not found, we fall back to the slower path.
	// This will be useful for the case where the buildID is already in the cache.
	buildID, err := buildid.FromFile(f)
	if err == nil {
		if obj, err := p.get(buildID); err == nil {
			p.buildIDCache.Put(path, buildID)
			return obj, nil
		}
	}
	return p.NewFile(f)
}

// var elfOpen = elf.Open       // Has a closer and keeps a reference to the file.
var elfNewFile = elf.NewFile // Doesn't have a closer and doesn't keep a reference to the file.

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
		if errors.Is(err, &elf.FormatError{}) {
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
		return nil, closer(fmt.Errorf("failed to get build ID for %s: %w", path, err))
	}
	if rErr := rewind(f); rErr != nil {
		p.metrics.openErrors.WithLabelValues(lvRewind).Inc()
		return nil, closer(rErr)
	}

	if v, ok := p.objCache.GetIfPresent(buildID); ok {
		// A file for this buildID is already in the cache, so close the file we just opened.
		// The existing file could be already closed, because we are done uploading it.
		// It's the callers responsibility to making sure the file is still open.
		if err := closer(nil); err != nil {
			return nil, err
		}
		val, ok := v.(ObjectFile)
		if !ok {
			return nil, fmt.Errorf("unexpected type in cache: %T", val)
		}

		p.metrics.opened.WithLabelValues(lvShared).Inc()
		return &val, nil
	}

	stat, err := f.Stat()
	if err != nil {
		p.metrics.openErrors.WithLabelValues(lvStat).Inc()
		return nil, fmt.Errorf("failed to get stats of the file: %w", err)
	}

	obj := ObjectFile{
		p: p,

		BuildID:  buildID,
		Path:     path,
		Size:     stat.Size(),
		Modtime:  stat.ModTime(),
		file:     f,
		openedAt: time.Now(),

		mtx: &sync.RWMutex{},
		// No need to keep another file descriptor for the file,
		// underlying ELF file already has one.
		elf: ef,
	}
	ref := &obj
	p.metrics.opened.WithLabelValues(lvSuccess).Inc()
	p.metrics.open.Inc()
	// https://pkg.go.dev/runtime#SetFinalizer
	// experiment: https://goplay.tools/snippet/Foc__-S4m7E
	// - Obj must be a pointer to an object allocated by using new, a composite literal address, or the address of a local variable.
	// The finalizer should be a function accepting a single argument of obj's type, and can have arbitrary ignored return values.
	// - For example, if p points to a struct, such as os.File, that contains a file descriptor d, and p has a finalizer that closes that file descriptor,
	// and if the last use of p in a function is a call to syscall.Write(p.d, buf, size), then p may be unreachable as soon as the program enters syscall.Write.
	// The finalizer may run at that moment, closing p.d, causing syscall.Write to fail because it is writing to a closed file descriptor
	// (or, worse, to an entirely different file descriptor opened by a different goroutine).
	// To avoid this problem, call KeepAlive(p) after the call to syscall.Write.
	runtime.SetFinalizer(ref, func(obj *ObjectFile) error {
		return errors.Join(obj.close(), f.Close())
	})
	p.buildIDCache.Put(path, buildID)
	p.objCache.Put(buildID, obj)
	return ref, nil
}

// Close closes the pool and all the files in it.
func (p *Pool) Close() error {
	// Closing cache will remove all the entries.
	// While removing the entries, the onRemoval function will be called,
	// and the files will be closed.
	return errors.Join(p.objCache.Close(), p.buildIDCache.Close())
}

// stats returns the stats of the pool.
// just for testing.
func (p *Pool) stats() *burrow.Stats {
	s := &burrow.Stats{}
	p.objCache.Stats(s)
	return s
}
