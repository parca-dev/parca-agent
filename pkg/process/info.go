// Copyright 2023 The Parca Authors
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

package process

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
	"github.com/puzpuzpuz/xsync/v2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type DebuginfoManager interface {
	ShouldInitiateUpload(context.Context, string) (bool, error)
	UploadMapping(context.Context, *Mapping) error
	Close() error
}

// TODO: Unify PID types.
type LabelManager interface {
	Fetch(ctx context.Context, pid int) error
	LabelSet(ctx context.Context, pid int) (model.LabelSet, error)
}

type Cache[K comparable, V any] interface {
	Add(K, V)
	Get(K) (V, bool)
	Peek(K) (V, bool)
	Remove(K)
}

const (
	lvSuccess = "success"
	lvFail    = "fail"
	lvShared  = "shared"

	lvAlreadyClosed        = "already_closed"
	lvShouldInitiateUpload = "should_initiate_upload"
	lvUnknown              = "unknown"
)

type metrics struct {
	fetchAttempts    prometheus.Counter
	fetched          *prometheus.CounterVec
	fetchDuration    prometheus.Histogram
	get              prometheus.Counter
	uploadErrors     *prometheus.CounterVec
	metadataDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		fetchAttempts: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_fetch_attempts_total",
			Help: "Total number of debug information load attempts.",
		}),
		fetched: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_fetched_total",
			Help: "Total number of debug information loads.",
		}, []string{"result"}),
		fetchDuration: promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Name:                        "parca_agent_process_info_fetch_duration_seconds",
			Help:                        "Duration of debug information loads.",
			NativeHistogramBucketFactor: 1.1,
		}),
		get: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_process_info_get_total",
			Help: "Total number of debug information gets.",
		}),
		uploadErrors: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_process_info_upload_errors_total",
			Help: "Total number of debug information upload errors.",
		}, []string{"type"}),
		metadataDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:                        "parca_agent_process_info_metadata_fetch_duration_seconds",
			Help:                        "Duration of metadata fetches.",
			NativeHistogramBucketFactor: 1.1,
		}),
	}
	m.fetched.WithLabelValues(lvSuccess)
	m.fetched.WithLabelValues(lvFail)
	m.fetched.WithLabelValues(lvShared)
	m.uploadErrors.WithLabelValues(lvShouldInitiateUpload)
	m.uploadErrors.WithLabelValues(lvAlreadyClosed)
	m.uploadErrors.WithLabelValues(lvUnknown)
	return m
}

type InfoManager struct {
	logger  log.Logger
	tracer  trace.Tracer
	metrics *metrics

	cache                     Cache[int, Info]
	shouldInitiateUploadCache Cache[string, struct{}]
	uploadInflight            *xsync.MapOf[string, struct{}]

	procFS           procfs.FS
	objFilePool      *objectfile.Pool
	mapManager       *MapManager
	debuginfoManager DebuginfoManager
	labelManager     LabelManager

	uploadJobQueue chan *uploadJob
	uploadJobPool  *sync.Pool
}

func NewInfoManager(
	logger log.Logger,
	tracer trace.Tracer,
	reg prometheus.Registerer,
	proceFS procfs.FS,
	objFilePool *objectfile.Pool,
	mm *MapManager,
	dim DebuginfoManager,
	lm LabelManager,
	profilingDuration time.Duration,
	cacheTTL time.Duration,
) *InfoManager {
	im := &InfoManager{
		logger:  logger,
		tracer:  tracer,
		metrics: newMetrics(reg),
		cache: cache.NewLRUCacheWithTTL[int, Info](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "process_info"}, reg),
			1024,
			12*profilingDuration,
			cache.CacheWithTTLOptions{
				RemoveExpiredOnAdd: true,
			},
		),
		shouldInitiateUploadCache: cache.NewLRUCacheWithTTL[string, struct{}](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "debuginfo_should_initiate"}, reg),
			1024,
			cacheTTL,
		),
		uploadInflight:   xsync.NewMapOf[struct{}](),
		procFS:           proceFS,
		objFilePool:      objFilePool,
		mapManager:       mm,
		debuginfoManager: dim,
		labelManager:     lm,

		uploadJobQueue: make(chan *uploadJob, 128),
		uploadJobPool: &sync.Pool{
			New: func() interface{} {
				return &uploadJob{}
			},
		},
	}
	return im
}

type InterpreterType uint64

const (
	None InterpreterType = iota
	Ruby
)

func (it InterpreterType) String() string {
	switch it {
	case None:
		return "<not an interpreter>"
	case Ruby:
		return "Ruby"
	default:
		return "<no string found>"
	}
}

type Interpreter struct {
	Type              InterpreterType
	Version           string
	MainThreadAddress uint64
}

type Info struct {
	im  *InfoManager
	pid int

	// TODO(kakkoyun): Put all the necessary (following) references in this struct.
	// - PerfMaps, JITDUMP, etc.
	//   * "/proc/%d/root/tmp/perf-%d.map" or "/proc/%d/root/tmp/perf-%d.dump" for PerfMaps
	//   * "/proc/%d/root/jit-%d.dump" for JITDUMP
	// - Unwind Information
	Interpreter *Interpreter
	Mappings    Mappings
}

// fetchRubyInterpreterInfo receives a process pid and memory mappings and
// figures out whether it might be a Ruby interpreter. In that case, it
// returns an `Interpreter` structure with the data that is needed by rbperf
// (https://github.com/javierhonduco/rbperf) to walk Ruby stacks.
func fetchRubyInterpreterInfo(pid int, mappings Mappings) (*Interpreter, error) {
	var (
		rubyBaseAddress    *uint64
		librubyBaseAddress *uint64
		librubyPath        string
	)

	// Find the load address for the interpreter.
	for _, mapping := range mappings {
		if strings.Contains(mapping.Pathname, "ruby") {
			startAddr := uint64(mapping.StartAddr)
			rubyBaseAddress = &startAddr
			break
		}
	}

	// Find the dynamically loaded libruby, if it exists.
	for _, mapping := range mappings {
		if strings.Contains(mapping.Pathname, "libruby") {
			startAddr := uint64(mapping.StartAddr)
			librubyPath = mapping.Pathname
			librubyBaseAddress = &startAddr
			break
		}
	}

	// If we can't find either, this is most likely not a Ruby
	// process.
	if rubyBaseAddress == nil && librubyBaseAddress == nil {
		return nil, fmt.Errorf("does not look like a Ruby Process")
	}

	var rubyExecutable string
	if librubyBaseAddress == nil {
		rubyExecutable = path.Join("/proc/", fmt.Sprintf("%d", pid), "/exe")
	} else {
		rubyExecutable = path.Join("/proc/", fmt.Sprintf("%d", pid), "/root/", librubyPath)
	}

	// Read the Ruby version.
	//
	// PERF(javierhonduco): Using Go's ELF reader in the stdlib is very
	// expensive. Do this in a streaming fashion rather than loading everything
	// at once.
	elfFile, err := elf.Open(rubyExecutable)
	if err != nil {
		return nil, fmt.Errorf("error opening ELF: %w", err)
	}

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("error reading ELF symbols: %w", err)
	}

	rubyVersion := ""
	for _, symbol := range symbols {
		if symbol.Name == "ruby_version" {
			rubyVersionBuf := make([]byte, symbol.Size-1)
			address := symbol.Value
			f, err := os.Open(rubyExecutable)
			if err != nil {
				return nil, fmt.Errorf("error opening ruby executable: %w", err)
			}

			_, err = f.Seek(int64(address), io.SeekStart)
			if err != nil {
				return nil, err
			}

			_, err = f.Read(rubyVersionBuf)
			if err != nil {
				return nil, err
			}

			rubyVersion = string(rubyVersionBuf)
		}
	}

	if rubyVersion == "" {
		return nil, fmt.Errorf("could not find Ruby version")
	}

	splittedVersion := strings.Split(rubyVersion, ".")
	major, err := strconv.Atoi(splittedVersion[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse version: %w", err)
	}
	minor, err := strconv.Atoi(splittedVersion[1])
	if err != nil {
		return nil, fmt.Errorf("could not parse version: %w", err)
	}

	var vmPointerSymbol string
	if major == 2 && minor >= 5 {
		vmPointerSymbol = "ruby_current_vm_ptr"
	} else {
		vmPointerSymbol = "ruby_current_vm"
	}

	// We first try to find the symbol in the symbol table, and then in
	// the dynamic symbol table.

	mainThreadAddress := uint64(0)
	for _, symbol := range symbols {
		// TODO(javierhonduco): Using contains is a bit of a hack. Ideally
		// we would like to find out which exact symbol to look for depending
		// on the Ruby version.
		if strings.Contains(symbol.Name, vmPointerSymbol) {
			mainThreadAddress = symbol.Value
		}
	}

	if mainThreadAddress == 0 {
		dynSymbols, err := elfFile.DynamicSymbols()
		if err != nil {
			return nil, fmt.Errorf("error reading dynamic ELF symbols: %w", err)
		}
		for _, symbol := range dynSymbols {
			// TODO(javierhonduco): Same as above.
			if strings.Contains(symbol.Name, vmPointerSymbol) {
				mainThreadAddress = symbol.Value
			}
		}
	}

	if mainThreadAddress == 0 {
		return nil, fmt.Errorf("mainThreadAddress should never be zero")
	}

	if librubyBaseAddress == nil {
		mainThreadAddress += *rubyBaseAddress
	} else {
		mainThreadAddress += *librubyBaseAddress
	}

	interp := Interpreter{
		Ruby,
		rubyVersion,
		mainThreadAddress,
	}

	return &interp, nil
}

// fetchInterpreterInfo attempts to fetch interpreter information
// for each supported interpreter. Once one is found, it will be
// returned.
func fetchInterpreterInfo(pid int, mappings Mappings) *Interpreter {
	rubyInfo, err := fetchRubyInterpreterInfo(pid, mappings)
	if err == nil {
		return rubyInfo
	}

	return nil
}

func (i Info) Labels(ctx context.Context) (model.LabelSet, error) {
	ctx, span := i.im.tracer.Start(ctx, "ProcessInfoManager.Info.Labels")
	defer span.End()

	// NOTICE: Caching is not necessary here since the label set is already cached in the label manager.
	return i.im.labelManager.LabelSet(ctx, i.pid)
}

func (im *InfoManager) Fetch(ctx context.Context, pid int) (Info, error) {
	im.metrics.fetchAttempts.Inc()

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Fetch")
	defer span.End()

	return im.fetch(ctx, pid)
}

// Fetch collects the required information for a process and stores it for future needs.
func (im *InfoManager) fetch(ctx context.Context, pid int) (info Info, err error) { //nolint:nonamedreturns
	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	info, exists := im.cache.Peek(pid)
	if exists {
		im.ensureDebuginfoUploaded(ctx, info.Mappings)
		return info, nil
	}

	now := time.Now()
	defer func() {
		if err != nil {
			im.metrics.fetched.WithLabelValues(lvFail).Inc()
		} else {
			im.metrics.fetched.WithLabelValues(lvSuccess).Inc()
			im.metrics.fetchDuration.Observe(time.Since(now).Seconds())
		}
	}()

	// Any operation in this block will be executed only once for a given pid.
	// However, it needs to be fast as possible since it will block other goroutines.
	// And to avoid missing information for the short lived processes, the extraction and finding of debug information
	// should be done as soon as possible.

	proc, err := im.procFS.Proc(pid)
	if err != nil {
		return Info{}, fmt.Errorf("failed to open proc %d: %w", pid, err)
	}
	exe, err := proc.Executable()
	if err != nil {
		return Info{}, fmt.Errorf("failed to get executable for proc %d: %w", pid, err)
	}
	// Cache the executable path for future needs.
	path := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), exe)
	if !(strings.Contains(path, "(deleted)") || strings.Contains(path, "memfd:")) {
		_, err = im.objFilePool.Open(path)
		if err != nil {
			return Info{}, fmt.Errorf("failed to get executable object file for %s: %w", path, err)
		}
	}

	// Get the mappings of the process. This caches underlying object files for future needs.
	mappings, err := im.mapManager.MappingsForPID(pid)
	if err != nil {
		return Info{}, err
	}

	// Upload debug information of the discovered object files.
	im.ensureDebuginfoUploaded(ctx, mappings)

	// No matter what happens with the debug information, we should continue.
	// And cache other process information.
	info = Info{
		im:          im,
		pid:         pid,
		Mappings:    mappings,
		Interpreter: fetchInterpreterInfo(pid, mappings),
	}

	im.cache.Add(pid, info)

	now = time.Now()
	defer func() {
		im.metrics.metadataDuration.Observe(time.Since(now).Seconds())
	}()
	// Warm up the label manager cache. Best effort.
	if lErr := im.labelManager.Fetch(ctx, pid); lErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to warm up label manager cache: %w", lErr))
	}
	return info, err
}

// Info returns the cached information for the given process.
func (im *InfoManager) Info(ctx context.Context, pid int) (Info, error) {
	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.Info")
	defer span.End()

	im.metrics.get.Inc()

	info, ok := im.cache.Get(pid)
	if ok {
		return info, nil
	}

	return im.fetch(ctx, pid)
}

// ensureDebuginfoUploaded extracts the debug information of the given mappings and uploads them to the debuginfo manager.
// It is a best effort operation, so it will continue even if it fails to ensure debug information of a mapping uploaded.
func (im *InfoManager) ensureDebuginfoUploaded(ctx context.Context, mappings Mappings) {
	if im.debuginfoManager == nil {
		return
	}

	for _, m := range mappings {
		if !m.containsDebuginfoToUpload {
			// Nothing to do for mappings without debuginfo.
			continue
		}

		// Doing this here prevents us from launching a goroutine just to check
		// the cache, which most of the time will be a hit.
		if _, ok := im.shouldInitiateUploadCache.Get(m.BuildID); ok {
			// The debug information of this mapping is already uploaded.
			continue
		}

		if _, exists := im.uploadInflight.LoadOrStore(m.BuildID, struct{}{}); exists {
			// The debug information of this mapping is already being uploaded.
			continue
		}

		// Schedule the debug information upload.
		im.schedule(ctx, m)
	}
}

func (im *InfoManager) schedule(ctx context.Context, m *Mapping) {
	j := im.uploadJobPool.Get().(*uploadJob) //nolint:forcetypeassert
	j.populate(ctx, m)

	defer func() {
		if r := recover(); r != nil {
			// Probably the upload job queue is closed.
			// That means we are shutting down.
			level.Warn(im.logger).Log("msg", "failed to schedule mapping upload", "err", r)
		}
	}()

	select {
	case <-ctx.Done():
		// Just to keep things clean.
		j.reset()
		im.uploadJobPool.Put(j)
		return
	case im.uploadJobQueue <- j:
	}
}

type uploadJob struct {
	ctx     context.Context //nolint:containedctx
	mapping *Mapping
}

func (j *uploadJob) populate(ctx context.Context, mapping *Mapping) {
	j.ctx = ctx
	j.mapping = mapping
}

func (j *uploadJob) reset() {
	j.ctx = nil
	j.mapping = nil
}

func (im *InfoManager) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancelCause(ctx)
	defer cancel(fmt.Errorf("process  info manager: %w", ctx.Err()))

	// Start the upload workers.
	for i := 0; i < 16; i++ {
		go func() {
			for {
				select {
				case <-wctx.Done():
					return
				case j, open := <-im.uploadJobQueue:
					if !open {
						return
					}

					// nolint:contextcheck
					im.uploadMapping(j.ctx, j.mapping)
					im.uploadInflight.Delete(j.mapping.BuildID)

					j.reset()
					im.uploadJobPool.Put(j)
				}
			}
		}()
	}

	// Wait for the context to be done.
	<-ctx.Done()
	return nil
}

func (im *InfoManager) uploadMapping(ctx context.Context, m *Mapping) {
	if err := ctx.Err(); err != nil {
		return
	}

	ctx, span := im.tracer.Start(ctx, "ProcessInfoManager.ensureDebuginfoUploaded.mapping")
	span.SetAttributes(attribute.Int("pid", m.PID))
	defer span.End() // The span is initially started in the for loop.

	// All the caches and references are based on the source file's buildID.

	shouldInitiateUpload, err := im.debuginfoManager.ShouldInitiateUpload(ctx, m.BuildID)
	if err != nil {
		im.metrics.uploadErrors.WithLabelValues(lvShouldInitiateUpload).Inc()
		err = fmt.Errorf("failed to check whether build ID exists: %w", err)
		level.Debug(im.logger).Log("msg", "upload mapping", "err", err, "buildid", m.BuildID, "filepath", m.AbsolutePath())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}

	if !shouldInitiateUpload {
		im.shouldInitiateUploadCache.Add(m.BuildID, struct{}{})
		return // The debug information is already uploaded.
	}

	if err := im.debuginfoManager.UploadMapping(ctx, m); err != nil {
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			im.metrics.uploadErrors.WithLabelValues(lvAlreadyClosed).Inc()
			return
		}
		im.metrics.uploadErrors.WithLabelValues(lvUnknown).Inc()
		err = fmt.Errorf("failed to ensure debug information uploaded: %w", err)
		level.Error(im.logger).Log("msg", "upload mapping", "err", err, "buildid", m.BuildID, "filepath", m.AbsolutePath())
		span.RecordError(err)
		return
	}
}

func (im *InfoManager) Close() error {
	close(im.uploadJobQueue)
	return nil
}
