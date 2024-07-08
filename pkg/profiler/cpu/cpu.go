// Copyright 2022-2024 The Parca Authors
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

package cpu

import "C" //nolint:all

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/puzpuzpuz/xsync/v3"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/cpuinfo"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	parcalogger "github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/pprof"
	"github.com/parca-dev/parca-agent/pkg/profile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	bpfmaps "github.com/parca-dev/parca-agent/pkg/profiler/cpu/bpf/maps"
	bpfmetrics "github.com/parca-dev/parca-agent/pkg/profiler/cpu/bpf/metrics"
	bpfprograms "github.com/parca-dev/parca-agent/pkg/profiler/cpu/bpf/programs"
	"github.com/parca-dev/parca-agent/pkg/rlimit"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

const (
	configKey = "unwinder_config"
)

// UnwinderConfig must be synced to the C definition.
type UnwinderConfig struct {
	FilterProcesses             bool
	VerboseLogging              bool
	MixedStackWalking           bool
	PythonEnable                bool
	RubyEnabled                 bool
	JavaEnabled                 bool
	CollectCustomLabels         bool
	Padding                     bool
	RateLimitUnwindInfo         uint32
	RateLimitProcessMappings    uint32
	RateLimitRefreshProcessInfo uint32
	RateLimitRead               uint32
}

type Config struct {
	ProfilingDuration          time.Duration
	ProfilingSamplingFrequency uint64

	PerfEventBufferPollInterval       time.Duration
	PerfEventBufferProcessingInterval time.Duration
	PerfEventBufferWorkerCount        int

	MemlockRlimit uint64

	DebugProcessNames []string

	DWARFUnwindingDisabled         bool
	DWARFUnwindingMixedModeEnabled bool
	BPFVerboseLoggingEnabled       bool
	BPFEventsBufferSize            uint32

	PythonUnwindingEnabled bool
	RubyUnwindingEnabled   bool
	JavaUnwindingEnabled   bool

	RateLimitUnwindInfo         uint32
	RateLimitProcessMappings    uint32
	RateLimitRefreshProcessInfo uint32
	RateLimitRead               uint32

	CollectCustomLabels bool
}

func (c Config) DebugModeEnabled() bool {
	return len(c.DebugProcessNames) > 0
}

type requestReadCacheKey struct {
	Pid  int32
	Addr uint64
}

type CPU struct {
	config *Config

	logger  log.Logger
	reg     prometheus.Registerer
	metrics *metrics

	processInfoManager profiler.ProcessInfoManager
	profileConverter   *pprof.Manager
	profileStore       profiler.ProfileStore

	// Notify that the BPF program was loaded.
	bpfProgramLoaded chan bool
	bpfMaps          *bpfmaps.Maps

	framePointerCache unwind.FramePointerCache
	requestReadCache  *cache.CacheWithTTL[requestReadCacheKey, struct{}]
	interpSymTab      profile.InterpreterSymbolTable

	byteOrder binary.ByteOrder

	mtx                            *sync.RWMutex
	lastError                      error
	processLastErrors              map[int]error
	failedReasons                  map[int]profiler.UnwindFailedReasons
	processErrorTracker            *errorTracker
	lastSuccessfulProfileStartedAt time.Time
	lastProfileStartedAt           time.Time
	objFilePool                    *objectfile.Pool

	cpus   cpuinfo.CPUSet
	finder *debuginfo.Finder
}

type PidEventPayload struct {
	Type                         uint8
	Padding1, Padding2, Padding3 uint8
	Pid                          int32
}

type RequestReadPayload struct {
	Type                         uint8
	Padding1, Padding2, Padding3 uint8
	Pid                          int32
	Addr                         uint64
}

func NewCPUProfiler(
	logger log.Logger,
	reg prometheus.Registerer,
	processInfoManager profiler.ProcessInfoManager,
	compilerInfoManager *runtime.CompilerInfoManager,
	profileConverter *pprof.Manager,
	profileWriter profiler.ProfileStore,
	config *Config,
	bpfProgramLoaded chan bool,
	objFilePool *objectfile.Pool,
	cpus cpuinfo.CPUSet,
	finder *debuginfo.Finder,
) *CPU {
	return &CPU{
		config: config,

		logger:  logger,
		reg:     reg,
		metrics: newMetrics(reg),

		processInfoManager: processInfoManager,
		profileConverter:   profileConverter,
		profileStore:       profileWriter,

		// CPU profiler specific caches.
		framePointerCache: unwind.NewHasFramePointersCache(logger, reg, compilerInfoManager),
		// Cache for debouncing /proc/<pid>/mem reads: only attempt to read the
		// same pid and address every 10 seconds at most.
		requestReadCache: cache.NewLRUCacheWithTTL[requestReadCacheKey, struct{}](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": "request_read"}, reg),
			10000,
			time.Second*10),

		byteOrder: byteorder.GetHostByteOrder(),

		mtx: &sync.RWMutex{},
		// increase cache length if needed to track more errors
		processErrorTracker: newErrorTracker(logger, reg, "no_text_section_error_tracker"),

		bpfProgramLoaded: bpfProgramLoaded,
		objFilePool:      objFilePool,
		cpus:             cpus,
		finder:           finder,
	}
}

func (p *CPU) Name() string {
	return "parca_agent_cpu"
}

func (p *CPU) LastProfileStartedAt() time.Time {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastProfileStartedAt
}

func (p *CPU) LastError() error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastError
}

func (p *CPU) ProcessLastErrors() map[int]error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.processLastErrors
}

// FailedReasons gets a map of PID to reasons unwinding failed for that PID
// during the current profiling loop.
func (p *CPU) FailedReasons() map[int]profiler.UnwindFailedReasons {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.failedReasons
}

// loadBPFModules loads the BPF programs and maps.
// Also adjusts the unwind shards to the highest possible value.
// And configures shared maps between BPF programs.
func loadBPFModules(logger log.Logger, reg prometheus.Registerer, memlockRlimit uint64, config Config, ofp *objectfile.Pool, finder *debuginfo.Finder) (*libbpf.Module, *bpfmaps.Maps, error) {
	var lerr error

	maxLoadAttempts := 10
	unwindShards := uint32(bpfmaps.MaxUnwindShards)

	bpfObj, err := bpfprograms.OpenNative()
	if err != nil {
		return nil, nil, err
	}

	libbpf.SetLoggerCbs(parcalogger.NewLibbpfLogCallbacks(logger))

	var (
		rbperf *libbpf.Module
		pyperf *libbpf.Module
		jvm    *libbpf.Module
	)
	if config.RubyUnwindingEnabled {
		// rbperf
		rbperfBPFObj, err := bpfprograms.OpenRbperf()
		if err != nil {
			return nil, nil, err
		}

		rbperf, err = libbpf.NewModuleFromBufferArgs(libbpf.NewModuleArgs{
			BPFObjBuff: rbperfBPFObj,
			BPFObjName: "parca-rbperf",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("new bpf module: %w", err)
		}
		level.Info(logger).Log("msg", "loaded rbperf BPF module")
	}

	if config.PythonUnwindingEnabled {
		// pyperf
		pyperfBPFObj, err := bpfprograms.OpenPyperf()
		if err != nil {
			return nil, nil, err
		}

		pyperf, err = libbpf.NewModuleFromBufferArgs(libbpf.NewModuleArgs{
			BPFObjBuff: pyperfBPFObj,
			BPFObjName: "parca-pyperf",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("new bpf module: %w", err)
		}
		level.Info(logger).Log("msg", "loaded pyperf BPF module")
	}

	if config.JavaUnwindingEnabled {
		// jvm
		jvmBPFObj, err := bpfprograms.OpenJVM()
		if err != nil {
			return nil, nil, err
		}

		jvm, err = libbpf.NewModuleFromBufferArgs(libbpf.NewModuleArgs{
			BPFObjBuff: jvmBPFObj,
			BPFObjName: "parca-jvm",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("new bpf module: %w", err)
		}
		level.Info(logger).Log("msg", "loaded jvm BPF module")
	}

	bpfmapsProcessCache := bpfmaps.NewProcessCache(logger, reg)
	syncedUnwinderInfo := cache.NewLRUCache[int, runtime.UnwinderInfo](
		prometheus.WrapRegistererWith(prometheus.Labels{"cache": "synced_unwinder_info"}, reg),
		bpfmaps.MaxCachedProcesses/10,
	)

	// Adaptive unwind shard count sizing.
	for i := 0; i < maxLoadAttempts; i++ {
		native, err := libbpf.NewModuleFromBufferArgs(libbpf.NewModuleArgs{
			BPFObjBuff: bpfObj,
			BPFObjName: "parca-native",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("new bpf module: %w", err)
		}

		// Must be called after bpf.NewModuleFromBufferArgs to avoid limit override.
		rLimit, err := rlimit.BumpMemlock(memlockRlimit, memlockRlimit)
		if err != nil {
			return nil, nil, fmt.Errorf("bump memlock: %w", err)
		}
		level.Debug(logger).Log("msg", "actual memory locked rlimit", "cur", rlimit.HumanizeRLimit(rLimit.Cur), "max", rlimit.HumanizeRLimit(rLimit.Max))

		modules := map[bpfprograms.ProfilerModuleType]*libbpf.Module{
			bpfprograms.NativeModule: native,
			bpfprograms.RbperfModule: rbperf,
			bpfprograms.PyperfModule: pyperf,
			bpfprograms.JVMModule:    jvm,
		}

		// Maps must be initialized before loading the BPF code.
		bpfMaps, err := bpfmaps.New(
			logger,
			reg,
			modules,
			ofp,
			bpfmapsProcessCache,
			syncedUnwinderInfo,
			finder,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize eBPF maps: %w", err)
		}

		if config.DWARFUnwindingDisabled {
			// Even if DWARF-based unwinding is disabled, either due to the user passing the flag to disable it or running on arm64, still
			// create a handful of shards to ensure that when it is enabled we can at least create some shards. Basically we want to ensure
			// that we catch any potential issues as early as possible.
			unwindShards = uint32(5)
		}

		level.Debug(logger).Log("msg", "attempting to create unwind shards", "count", unwindShards)
		if err := bpfMaps.AdjustMapSizes(config.DebugModeEnabled(), unwindShards, config.BPFEventsBufferSize); err != nil {
			return nil, nil, fmt.Errorf("failed to adjust map sizes: %w", err)
		}
		level.Debug(logger).Log("msg", "created unwind shards", "count", unwindShards)

		level.Debug(logger).Log("msg", "initializing BPF global variables")
		if err := native.InitGlobalVariable(configKey, UnwinderConfig{
			FilterProcesses:             config.DebugModeEnabled(),
			VerboseLogging:              config.BPFVerboseLoggingEnabled,
			MixedStackWalking:           config.DWARFUnwindingMixedModeEnabled,
			PythonEnable:                config.PythonUnwindingEnabled,
			RubyEnabled:                 config.RubyUnwindingEnabled,
			JavaEnabled:                 config.JavaUnwindingEnabled,
			CollectCustomLabels:         config.CollectCustomLabels,
			Padding:                     false,
			RateLimitUnwindInfo:         config.RateLimitUnwindInfo,
			RateLimitProcessMappings:    config.RateLimitProcessMappings,
			RateLimitRefreshProcessInfo: config.RateLimitRefreshProcessInfo,
			RateLimitRead:               config.RateLimitRead,
		}); err != nil {
			return nil, nil, fmt.Errorf("init global variable: %w", err)
		}

		if config.RubyUnwindingEnabled {
			if err := rbperf.InitGlobalVariable("verbose", config.BPFVerboseLoggingEnabled); err != nil {
				return nil, nil, fmt.Errorf("rbperf: init global variable: %w", err)
			}
		}

		if config.PythonUnwindingEnabled {
			if err := pyperf.InitGlobalVariable("verbose", config.BPFVerboseLoggingEnabled); err != nil {
				return nil, nil, fmt.Errorf("pyperf: init global variable: %w", err)
			}
		}

		if config.JavaUnwindingEnabled {
			if err := jvm.InitGlobalVariable("verbose", config.BPFVerboseLoggingEnabled); err != nil {
				return nil, nil, fmt.Errorf("jvm: init global variable: %w", err)
			}
		}

		level.Debug(logger).Log("msg", "loading BPF object for native unwinder")
		lerr = native.BPFLoadObject()
		if lerr == nil {
			// Must be called before loading the interpreter stack walkers.
			err := bpfMaps.ReuseMaps()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to reuse maps: %w", err)
			}

			if config.RubyUnwindingEnabled {
				level.Debug(logger).Log("msg", "loading BPF object for ruby unwinder")
				err = rbperf.BPFLoadObject()
				if err != nil {
					return nil, nil, fmt.Errorf("failed to load rbperf: %w", err)
				}
			}

			if config.PythonUnwindingEnabled {
				level.Debug(logger).Log("msg", "loading BPF object for python unwinder")
				err = pyperf.BPFLoadObject()
				if err != nil {
					return nil, nil, fmt.Errorf("failed to load pyperf: %w", err)
				}
			}

			if config.JavaUnwindingEnabled {
				level.Debug(logger).Log("msg", "loading BPF object for JVM unwinder")
				err = jvm.BPFLoadObject()
				if err != nil {
					return nil, nil, fmt.Errorf("failed to load jvm: %w", err)
				}
			}

			level.Debug(logger).Log("msg", "updating programs map")
			err = bpfMaps.UpdateTailCallsMap()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to update programs map: %w", err)
			}

			level.Debug(logger).Log("msg", "updating interpreter data")
			err = bpfMaps.SetUnwinderData()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to set interpreter data: %w", err)
			}

			return native, bpfMaps, nil
		}

		// There's not enough free memory for these many unwind shards, let's retry with half
		// as many.
		if errors.Is(lerr, syscall.ENOMEM) {
			if err := bpfMaps.Close(); err != nil { // Only required when we want to retry.
				return nil, nil, fmt.Errorf("failed to cleanup previously created bpfmaps: %w", err)
			}
			unwindShards /= 2
		} else {
			break
		}
	}

	level.Error(logger).Log("msg", "could not create unwind info shards", "lastError", lerr)
	return nil, nil, lerr
}

func handleRequestRead(pid int, addr uint64) ([]byte, error) {
	filePath := "/proc/" + strconv.Itoa(pid) + "/mem"
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, 8)
	_, err = file.ReadAt(buffer, int64(addr))
	if err != nil {
		return nil, err
	}

	return buffer, nil
}

// listenEvents listens for events from the BPF program and handles them.
// It also listens for lost events and logs them.
func (p *CPU) listenEvents(ctx context.Context, wg *sync.WaitGroup, eventsChan <-chan []byte, lostChan <-chan uint64, requestUnwindInfoChan chan<- int) {
	prefetch := make(chan int, p.config.PerfEventBufferWorkerCount*4)
	refresh := make(chan int, p.config.PerfEventBufferWorkerCount*2)
	defer func() {
		close(prefetch)
		close(refresh)
	}()

	var (
		fetchInProgress   = xsync.NewMapOf[int, struct{}]()
		refreshInProgress = xsync.NewMapOf[int, struct{}]()
	)
	for i := 0; i < p.config.PerfEventBufferWorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pid, open := <-prefetch:
					if !open {
						level.Info(p.logger).Log("msg", "event loop ended, ending worker loop")
						return
					}
					_ = p.prefetchProcessInfo(ctx, pid)
					fetchInProgress.Delete(pid)
				case pid, open := <-refresh:
					if !open {
						level.Info(p.logger).Log("msg", "event loop ended, ending worker loop")
						return
					}

					err := func() error {
						defer refreshInProgress.Delete(pid)
						if err := p.fetchProcessInfoWithFreshMappings(ctx, pid); err != nil {
							return err
						}

						executable := fmt.Sprintf("/proc/%d/exe", pid)
						shouldUseFPByDefault, err := p.framePointerCache.HasFramePointers(executable) // nolint:contextcheck
						if err != nil {
							// It might not exist as reading procfs is racy. If the executable has no symbols
							// that we use as a heuristic to detect whether it has frame pointers or not,
							// we assume it does not and that we should generate the unwind information.
							level.Debug(p.logger).Log("msg", "frame pointer detection failed", "executable", executable, "err", err)
							if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, elf.ErrNoSymbols) {
								return err
							}
						}

						// Process information has been refreshed, now refresh the mappings and their unwind info.
						p.bpfMaps.RefreshProcessInfo(pid, shouldUseFPByDefault)
						return nil
					}()
					if err != nil {
						p.metrics.refreshInfoErrors.Inc()
						level.Warn(p.logger).Log("msg", "failed to refresh process info", "pid", pid, "err", err)
					}
				}
			}
		}()
	}

	for {
		select {
		case receivedBytes, open := <-eventsChan:
			if !open {
				return
			}
			if len(receivedBytes) == 0 {
				p.metrics.eventsReceived.WithLabelValues(labelEventEmpty).Inc()
				continue
			}

			if receivedBytes[0] == bpfmaps.RequestRead {
				var payload RequestReadPayload
				if err := binary.Read(bytes.NewBuffer(receivedBytes), p.bpfMaps.ByteOrder(), &payload); err != nil {
					level.Error(p.logger).Log("msg", "failed reading request read event payload",
						"payload", hex.EncodeToString(receivedBytes),
						"err", err, "byteOrder", p.bpfMaps.ByteOrder())
					continue
				}
				pid, addr := payload.Pid, payload.Addr
				key := requestReadCacheKey{pid, addr}
				if _, has := p.requestReadCache.Get(key); has {
					continue
				}
				p.requestReadCache.Add(key, struct{}{})
				if _, err := handleRequestRead(int(pid), addr); err != nil {
					level.Warn(p.logger).Log("msg", "failed reading memory", "pid", pid, "addr", addr, "err", err)
					p.metrics.requestReadAttempts.WithLabelValues(labelFailed)
				} else {
					p.metrics.requestReadAttempts.WithLabelValues(labelSuccess)
				}
				continue
			}

			var payload PidEventPayload
			if err := binary.Read(bytes.NewBuffer(receivedBytes), p.bpfMaps.ByteOrder(), &payload); err != nil {
				level.Error(p.logger).Log("msg", "failed reading event payload", "payload", hex.EncodeToString(receivedBytes), "err", err, "byteOrder", p.bpfMaps.ByteOrder())
				continue
			}
			pid, typ := int(payload.Pid), payload.Type

			switch {
			case typ == bpfmaps.RequestUnwindInformation:
				if p.config.DWARFUnwindingDisabled {
					continue
				}
				p.metrics.eventsReceived.WithLabelValues(labelEventUnwindInfo).Inc()
				// See onDemandUnwindInfoBatcher for consumer.
				requestUnwindInfoChan <- pid
			case typ == bpfmaps.RequestProcessMappings:
				p.metrics.eventsReceived.WithLabelValues(labelEventProcessMappings).Inc()
				if _, exists := fetchInProgress.LoadOrStore(pid, struct{}{}); exists {
					continue
				}
				prefetch <- pid
			case typ == bpfmaps.RequestRefreshProcInfo:
				p.metrics.eventsReceived.WithLabelValues(labelEventRefreshProcInfo).Inc()
				// Refresh mappings and their unwind info if they've changed.
				if _, exists := refreshInProgress.LoadOrStore(pid, struct{}{}); exists {
					continue
				}
				refresh <- pid
			}
		case lost, open := <-lostChan:
			if !open {
				return
			}
			p.metrics.eventsLost.Inc()
			level.Warn(p.logger).Log("msg", "lost events", "count", lost)
		default:
			time.Sleep(p.config.PerfEventBufferProcessingInterval)
		}
	}
}

func (p *CPU) prefetchProcessInfo(ctx context.Context, pid int) error {
	procInfo, err := p.processInfoManager.Fetch(ctx, pid)
	if err != nil {
		level.Debug(p.logger).Log("msg", "failed to prefetch process info", "pid", pid, "err", err)
		return fmt.Errorf("failed to prefetch process info: %w", err)
	}

	if procInfo.UnwinderInfo != nil {
		// AddUnwinderInfo is idempotent.
		err := p.bpfMaps.AddUnwinderInfo(pid, procInfo.UnwinderInfo)
		if err != nil {
			level.Debug(p.logger).Log("msg", "failed to call AddUnwinderInfo", "pid", pid, "err", err)
			return fmt.Errorf("failed to call AddUnwinderInfo: %w", err)
		}
	}
	return nil
}

// fetchProcessInfoWithFreshMappings fetches process information and makes sure its mappings are up-to-date.
func (p *CPU) fetchProcessInfoWithFreshMappings(ctx context.Context, pid int) error {
	procInfo, err := p.processInfoManager.FetchWithFreshMappings(ctx, pid)
	if err != nil {
		level.Debug(p.logger).Log("msg", "failed to fetch process info", "pid", pid, "err", err)
		return fmt.Errorf("failed to fetch process info: %w", err)
	}

	if procInfo.UnwinderInfo != nil {
		// AddUnwinderInfo is idempotent.
		err := p.bpfMaps.AddUnwinderInfo(pid, procInfo.UnwinderInfo)
		if err != nil {
			level.Debug(p.logger).Log("msg", "failed to call AddUnwinderInfo", "pid", pid, "err", err)
			return fmt.Errorf("failed to call AddUnwinderInfo: %w", err)
		}
	}
	return nil
}

// onDemandUnwindInfoBatcher batches PIDs sent from the BPF program when
// frame pointers and unwind information are not present.
//
// Waiting for as long as `duration` is important because `PersistUnwindTable`
// must be called to write the in-flight shard to the BPF map. This has been
// a hot path in the CPU profiles we take in Demo when we persisted the unwind
// tables after adding every pid.
func (p *CPU) onDemandUnwindInfoBatcher(ctx context.Context, requestUnwindInfoChannel <-chan int) {
	processEventBatcher(ctx, requestUnwindInfoChannel, 150*time.Millisecond, func(pids []int) {
		for _, pid := range pids {
			p.addUnwindTableForProcess(ctx, pid)
		}

		// Must be called after all the calls to `addUnwindTableForProcess`, as it's possible
		// that the current in-flight shard hasn't been written to the BPF map, yet.
		err := p.bpfMaps.PersistUnwindTable()
		if err != nil {
			// Don't bother logging errors if we're done, common in integration tests.
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, bpfmaps.ErrNeedMoreProfilingRounds) {
				p.metrics.unwindTablePersistErrors.WithLabelValues(labelNeedMoreProfilingRounds).Inc()
				level.Debug(p.logger).Log("msg", "PersistUnwindTable called to soon", "err", err)
			} else {
				p.metrics.unwindTablePersistErrors.WithLabelValues(labelOther).Inc()
				level.Error(p.logger).Log("msg", "PersistUnwindTable failed", "err", err)
			}
		}
	})
}

func (p *CPU) addUnwindTableForProcess(ctx context.Context, pid int) {
	executable := fmt.Sprintf("/proc/%d/exe", pid)
	shouldUseFPByDefault, err := p.framePointerCache.HasFramePointers(executable) // nolint:contextcheck
	if err != nil {
		// It might not exist as reading procfs is racy. If the executable has no symbols
		// that we use as a heuristic to detect whether it has frame pointers or not,
		// we assume it does not and that we should generate the unwind information.
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, elf.ErrNoSymbols) {
			level.Warn(p.logger).Log("msg", "frame pointer detection failed", "executable", executable, "err", err)
			p.metrics.unwindTableAddErrors.WithLabelValues(labelFpDetectionFailed).Inc()
			return
		} else {
			level.Debug(p.logger).Log("msg", "frame pointer detection failed", "executable", executable, "err", err)
		}
	}

	level.Debug(p.logger).Log("msg", "prefetching process info", "pid", pid)
	if err := p.prefetchProcessInfo(ctx, pid); err != nil {
		p.metrics.unwindTableAddErrors.WithLabelValues(labelPrefetchProcessInfoFailed).Inc()
		level.Warn(p.logger).Log("msg", "failed to add unwind table", "pid", pid, "err", err)
		return
	}

	level.Debug(p.logger).Log("msg", "adding unwind tables", "pid", pid)
	if err = p.bpfMaps.AddUnwindTableForProcess(pid, nil, true, shouldUseFPByDefault); err == nil {
		// Happy path.
		return
	}

	// Error handling,
	switch {
	case errors.Is(err, bpfmaps.ErrNeedMoreProfilingRounds):
		p.metrics.unwindTableAddErrors.WithLabelValues(labelNeedMoreProfilingRounds).Inc()
		level.Debug(p.logger).Log("msg", "PersistUnwindTable called to soon", "err", err)
	case errors.Is(err, os.ErrNotExist):
		p.metrics.unwindTableAddErrors.WithLabelValues(labelProcfsRace).Inc()
		level.Debug(p.logger).Log("msg", "failed to add unwind table due to a procfs race", "pid", pid, "err", err)
	case errors.Is(err, bpfmaps.ErrTooManyExecutableMappings):
		p.metrics.unwindTableAddErrors.WithLabelValues(labelTooManyMappings).Inc()
		level.Warn(p.logger).Log("msg", "failed to add unwind table due to having too many executable mappings", "pid", pid, "err", err)
	case errors.Is(err, buildid.ErrTextSectionNotFound):
		p.processErrorTracker.Track(pid, err)
	default:
		p.metrics.unwindTableAddErrors.WithLabelValues(labelOther).Inc()
		level.Warn(p.logger).Log("msg", "failed to add unwind table", "pid", pid, "err", err)
	}
}

// processEventBatcher batches PIDs sent from the BPF program.
//
// Waits for as long as `duration` and calls the `callback` function with a slice of PIDs.
func processEventBatcher(ctx context.Context, eventsChannel <-chan int, duration time.Duration, callback func([]int)) {
	batch := make([]int, 0)
	timerOn := false
	timer := &time.Timer{}
	for {
		select {
		case pid, open := <-eventsChannel:
			if !open {
				return
			}
			// We want to set a deadline whenever an event is received, if there is
			// no other deadline in progress. During this time period we'll batch
			// all the events received. Once time's up, we will pass the batch to
			// the callback.
			if !timerOn {
				timerOn = true
				timer = time.NewTimer(duration)
			}
			batch = append(batch, pid)
		case <-timer.C:
			// remove duplicates
			sort.Ints(batch)
			callback(slices.Compact(batch))
			batch = batch[:0]
			timerOn = false
			timer.Stop()
		}
	}
}

func (p *CPU) watchProcesses(ctx context.Context, pfs procfs.FS, matchers []*regexp.Regexp) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		pids := []int{}

		allThreads := func() procfs.Procs {
			allProcs, err := pfs.AllProcs()
			if err != nil {
				level.Error(p.logger).Log("msg", "failed to list processes", "err", err)
				return nil
			}

			allThreads := make(procfs.Procs, len(allProcs))
			for _, proc := range allProcs {
				threads, err := pfs.AllThreads(proc.PID)
				if err != nil {
					level.Debug(p.logger).Log("msg", "failed to list threads", "err", err)
					continue
				}
				allThreads = append(allThreads, threads...)
			}
			return allThreads
		}

		// Filter processes if needed.
		if p.config.DebugModeEnabled() {
			level.Debug(p.logger).Log("msg", "debug process matchers found, starting process watcher")

			for _, thread := range allThreads() {
				if thread.PID == 0 {
					continue
				}
				comm, err := thread.Comm()
				if err != nil {
					level.Debug(p.logger).Log("msg", "failed to read process name", "pid", thread.PID, "err", err)
					continue
				}

				if comm == "" {
					continue
				}

				for _, m := range matchers {
					if m.MatchString(comm) {
						level.Info(p.logger).Log("msg", "match found; debugging process", "pid", thread.PID, "comm", comm)
						pids = append(pids, thread.PID)
					}
				}
			}

			if len(pids) > 0 {
				level.Debug(p.logger).Log("msg", "updating debug pids map", "pids", fmt.Sprintf("%v", pids))
				// Only meant to be used for debugging, it is not safe to use in production.
				if err := p.bpfMaps.SetDebugPIDs(pids); err != nil {
					level.Error(p.logger).Log("msg", "failed to update debug pids map", "err", err)
				}
			} else {
				level.Debug(p.logger).Log("msg", "no processes matched the provided regex")
				if err := p.bpfMaps.SetDebugPIDs(nil); err != nil {
					level.Error(p.logger).Log("msg", "failed to update debug pids map", "err", err)
				}
			}
		} else {
			for _, thread := range allThreads() {
				pids = append(pids, thread.PID)
			}
		}
	}
}

func bpfCheck() error {
	var result error

	if support, err := libbpf.BPFProgramTypeIsSupported(libbpf.BPFProgTypePerfEvent); !support {
		result = errors.Join(result, fmt.Errorf("perf event program type not supported: %w", err))
	}

	if support, err := libbpf.BPFMapTypeIsSupported(libbpf.MapTypeStackTrace); !support {
		result = errors.Join(result, fmt.Errorf("stack trace map type not supported: %w", err))
	}

	if support, err := libbpf.BPFMapTypeIsSupported(libbpf.MapTypeHash); !support {
		result = errors.Join(result, fmt.Errorf("hash map type not supported: %w", err))
	}

	return result
}

func (p *CPU) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting cpu profiler")

	err := bpfCheck()
	if err != nil {
		return fmt.Errorf("bpf check: %w", err)
	}

	var matchers []*regexp.Regexp
	if p.config.DebugModeEnabled() {
		level.Info(p.logger).Log("msg", "process names specified, debugging processes", "matchers", strings.Join(p.config.DebugProcessNames, ", "))
		for _, exp := range p.config.DebugProcessNames {
			regex, err := regexp.Compile(exp)
			if err != nil {
				return fmt.Errorf("failed to compile regex: %w", err)
			}
			matchers = append(matchers, regex)
		}
	}

	// Don't return until all (or most) go routines spawned from here have finished.
	// This prevent spurious errors during testing and shutdown from worker threads
	// doing bpf things after the bpf module is closed.
	var wg sync.WaitGroup
	defer func() {
		// We don't want to hang forever here if we're panicking
		if r := recover(); r != nil {
			panic(r)
		}
		wg.Wait()
	}()

	level.Debug(p.logger).Log("msg", "loading BPF modules")
	native, bpfMaps, err := loadBPFModules(p.logger, p.reg, p.config.MemlockRlimit, *p.config, p.objFilePool, p.finder)
	if err != nil {
		return fmt.Errorf("load bpf program: %w", err)
	}
	defer native.Close()
	level.Debug(p.logger).Log("msg", "BPF modules loaded")

	p.bpfProgramLoaded <- true
	p.bpfMaps = bpfMaps

	// Get bpf metrics
	agentProc, err := procfs.Self() // pid of parca-agent
	if err != nil {
		level.Debug(p.logger).Log("msg", "error getting parca-agent pid", "err", err)
	}

	p.reg.MustRegister(bpfmetrics.NewCollector(p.logger, native, bpfmaps.PerCPUStatsMapName, agentProc.PID))

	// Period is the number of events between sampled occurrences.
	// By default we sample at 19Hz (19 times per second),
	// which is every ~0.05s or 52,631,578 nanoseconds (1 Hz = 1e9 ns).
	samplingPeriod := int64(1e9 / p.config.ProfilingSamplingFrequency)

	level.Debug(p.logger).Log("msg", "attaching perf event to all CPUs")
	for _, cpuRange := range p.cpus {
		for i := cpuRange.First; i <= cpuRange.Last; i++ {
			level.Debug(p.logger).Log("msg", "profiling CPU", "n", i)
			fd, err := unix.PerfEventOpen(&unix.PerfEventAttr{
				Type:   unix.PERF_TYPE_SOFTWARE,
				Config: unix.PERF_COUNT_SW_CPU_CLOCK,
				Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
				Sample: p.config.ProfilingSamplingFrequency,
				Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
			}, -1 /* pid */, int(i) /* cpu id */, -1 /* group */, 0 /* flags */)
			if err != nil {
				return fmt.Errorf("open perf event: %w", err)
			}

			// Do not close this fd manually as it will result in an error in the
			// best case, if the FD doesn't exist and in the worst case it will
			// close the wrong FD.
			//
			// The `Close` method on the module calls `bpf_link__destroy`, which calls
			// the link's `detach` function[2], that eventually, through the `bpf_link__detach_fd`
			// function it closes the link's FD[3].
			// [1]: https://github.com/aquasecurity/libbpfgo/blob/64458ba5a32013dda2d4f88838dde8456922333d/libbpfgo.go#L420
			// [2]: https://github.com/libbpf/libbpf/blob/master/src/libbpf.c#L9762
			// [3]: https://github.com/libbpf/libbpf/blob/master/src/libbpf.c#L9785

			prog, err := native.GetProgram(bpfprograms.ProgramName)
			if err != nil {
				return fmt.Errorf("get bpf program: %w", err)
			}

			// Because this is fd based, even if our program crashes or is ended
			// without proper shutdown, things get cleaned up appropriately.
			_, err = prog.AttachPerfEvent(fd)
			// Do not call `link.Destroy()`[1] as closing the module takes care of
			// it[2].
			// [1]: https://github.com/aquasecurity/libbpfgo/blob/64458ba5a32013dda2d4f88838dde8456922333d/libbpfgo.go#L240
			// [2]: https://github.com/aquasecurity/libbpfgo/blob/64458ba5a32013dda2d4f88838dde8456922333d/libbpfgo.go#L420
			if err != nil {
				return fmt.Errorf("attach perf event: %w", err)
			}
		}
	}

	// Record start time for first profile.
	p.mtx.Lock()
	p.lastProfileStartedAt = time.Now()
	p.mtx.Unlock()

	prog, err := native.GetProgram(bpfprograms.NativeUnwinderProgramName)
	if err != nil {
		return fmt.Errorf("get bpf program: %w", err)
	}
	programs, err := native.GetMap(bpfmaps.ProgramsMapName)
	if err != nil {
		return fmt.Errorf("get programs map: %w", err)
	}

	fd := prog.FileDescriptor()
	if err := programs.Update(unsafe.Pointer(&bpfprograms.NativeProgramFD), unsafe.Pointer(&fd)); err != nil {
		return fmt.Errorf("failure updating: %w", err)
	}

	if err := p.bpfMaps.Create(); err != nil {
		return fmt.Errorf("failed to create maps: %w", err)
	}

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return fmt.Errorf("failed to create procfs: %w", err)
	}

	spawn := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	if len(matchers) > 0 {
		// Update the debug pids map.
		spawn(func() {
			p.watchProcesses(ctx, pfs, matchers)
		})
	}

	// Process BPF events.
	var (
		eventsChan  = make(chan []byte, 30)
		lostChannel = make(chan uint64, 10)
	)
	perfBuf, err := native.InitPerfBuf("events", eventsChan, lostChannel, 64)
	if err != nil {
		return fmt.Errorf("failed to init perf buffer: %w", err)
	}
	perfBuf.Poll(int(p.config.PerfEventBufferPollInterval.Milliseconds()))

	requestUnwindInfoChannel := make(chan int, 30)

	spawn(func() {
		defer close(requestUnwindInfoChannel)
		p.listenEvents(ctx, &wg, eventsChan, lostChannel, requestUnwindInfoChannel)
	})
	spawn(func() {
		p.onDemandUnwindInfoBatcher(ctx, requestUnwindInfoChannel)
	})

	ticker := time.NewTicker(p.config.ProfilingDuration)
	defer ticker.Stop()

	level.Debug(p.logger).Log("msg", "start profiling loop")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		obtainStart := time.Now()
		rawData, failedReasons, err := p.obtainRawData(ctx)
		if err != nil {
			p.metrics.obtainAttempts.WithLabelValues(labelError).Inc()
			level.Warn(p.logger).Log("msg", "failed to obtain profiles from eBPF maps", "err", err)
			continue
		}

		p.metrics.obtainAttempts.WithLabelValues(labelSuccess).Inc()
		p.metrics.obtainDuration.Observe(time.Since(obtainStart).Seconds())

		groupedRawData := make(map[int]profile.ProcessRawData)

		for pid := range failedReasons {
			groupedRawData[pid] = profile.ProcessRawData{
				PID: profile.PID(pid),
			}
		}

		for _, perThreadRawData := range rawData {
			pid := int(perThreadRawData.PID)
			data, ok := groupedRawData[pid]
			if !ok {
				groupedRawData[pid] = profile.ProcessRawData{
					PID:        perThreadRawData.PID,
					RawSamples: perThreadRawData.RawSamples,
				}
				continue
			}

			groupedRawData[pid] = profile.ProcessRawData{
				PID:        perThreadRawData.PID,
				RawSamples: append(data.RawSamples, perThreadRawData.RawSamples...),
			}
		}

		processLastErrors := map[int]error{}
		for pid, perProcessRawData := range groupedRawData {
			processLastErrors[pid] = nil

			pi, err := p.processInfoManager.Info(ctx, pid)
			if err != nil {
				p.metrics.profileDrop.WithLabelValues(labelProfileDropReasonProcessInfo).Inc()
				level.Debug(p.logger).Log("msg", "failed to get process info", "pid", pid, "err", err)
				processLastErrors[pid] = err
				// We used to bail here but now we keep going to get error samples and samples from
				// short lived processes.
			}

			interpreterSymbolTable, err := p.interpreterSymbolTable(perProcessRawData.RawSamples)
			if err != nil {
				level.Debug(p.logger).Log("msg", "failed to get interpreter symbol table", "pid", pid, "err", err)
			}
			pprof, executableInfos := p.profileConverter.NewConverter(
				pfs,
				pid,
				pi.Mappings.Executables(),
				p.LastProfileStartedAt(),
				samplingPeriod,
				interpreterSymbolTable,
			).Convert(ctx, perProcessRawData.RawSamples, failedReasons[pid])

			labelSet, err := pi.Labels(ctx)
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to get process labels", "pid", pid, "err", err)
				processLastErrors[pid] = err
				continue
			}
			if len(labelSet) == 0 {
				level.Debug(p.logger).Log("msg", "profile dropped", "pid", pid)
				continue
			}
			// Add the profiler name as a label.
			// Uses labels.Merge under the hood, so it re-allocates the label set.
			// If we want to drop/disable a profiler, we should do it with another mechanism besides relabelling.
			labelSet = labels.WithProfilerName(labelSet, p.Name())

			if err := p.profileStore.Store(ctx, labelSet, pprof, executableInfos); err != nil {
				level.Warn(p.logger).Log("msg", "failed to write profile", "pid", pid, "err", err)
				processLastErrors[pid] = err
				continue
			}
		}
		p.report(err, processLastErrors, failedReasons)
	}
}

func (p *CPU) report(lastError error, processLastErrors map[int]error, failedReasons map[int]profiler.UnwindFailedReasons) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if lastError == nil {
		p.lastSuccessfulProfileStartedAt = p.lastProfileStartedAt
		p.lastProfileStartedAt = time.Now()
	}
	p.lastError = lastError
	p.processLastErrors = processLastErrors
	p.failedReasons = failedReasons
}

const (
	maxCustomLabels       = 16
	customLabelsMaxKeyLen = 64
	customLabelsMaxValLen = 64
)

type (
	// stackCountKey mirrors the struct in BPF program.
	// NOTICE: The memory layout and alignment of the struct currently matches the struct in BPF program.
	// However, keep in mind that Go compiler injects padding to align the struct fields to be a multiple of 8 bytes.
	// The Go spec says the address of a struct’s fields must be naturally aligned.
	// https://dave.cheney.net/2015/10/09/padding-is-hard
	// TODO(https://github.com/parca-dev/parca-agent/issues/207)
	stackCountKey struct {
		PID                int32
		TID                int32
		UserStackID        uint64
		KernelStackID      uint64
		InterpreterStackID uint64
		CustomLabelsID     uint64
	}

	customLabel struct {
		KeyLen uint32
		ValLen uint32
		Key    [customLabelsMaxKeyLen]byte
		Val    [customLabelsMaxValLen]byte
	}

	customLabelsArray struct {
		Len     int32
		Padding uint32
		Labels  [maxCustomLabels]customLabel
	}
)

type profileKey struct {
	pid            int32
	tid            int32
	customLabelsID uint64
}

// interpreterSymbolTable returns an up-to-date symbol table for the interpreter.
func (p *CPU) interpreterSymbolTable(samples []profile.RawSample) (profile.InterpreterSymbolTable, error) {
	if p.interpSymTab == nil {
		if err := p.updateInterpreterSymbolTable(); err != nil {
			// Return the old version of the symbol table if we failed to update it.
			return p.interpSymTab, err
		}
		return p.interpSymTab, nil
	}

	for _, sample := range samples {
		if sample.InterpreterStack == nil {
			continue
		}

		for _, frame := range sample.InterpreterStack {
			if frame.Status != profile.FrameStatusOk {
				continue
			}
			id := frame.Addr
			if _, ok := p.interpSymTab[uint32(id)]; !ok {
				if err := p.updateInterpreterSymbolTable(); err != nil {
					// Return the old version of the symbol table if we failed to update it.
					return p.interpSymTab, err
				}
				// We only need to update the symbol table once.
				return p.interpSymTab, nil
			}
		}
	}
	// The symbol table is up-to-date.
	return p.interpSymTab, nil
}

func (p *CPU) updateInterpreterSymbolTable() error {
	interpSymTab, err := p.bpfMaps.InterpreterSymbolTable()
	if err != nil {
		return fmt.Errorf("get interpreter symbol table: %w", err)
	}
	p.interpSymTab = interpSymTab
	return nil
}

// obtainProfiles collects profiles from the BPF maps.
func (p *CPU) obtainRawData(ctx context.Context) (profile.RawData, map[int]profiler.UnwindFailedReasons, error) {
	rawData := map[profileKey]map[bpfmaps.CombinedStack]uint64{}
	customLabelsMap := map[uint64]customLabelsArray{}

	it := p.bpfMaps.StackCounts.Iterator()
	warnedOnce := false
	nCustomLabels := 0
	for it.Next() {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		// This byte slice is only valid for this iteration, so it must be
		// copied if we want to do anything with it outside this loop.
		keyBytes := it.Key()

		var key stackCountKey
		// NOTICE: This works because the key struct in Go and the key struct in C has exactly the same memory layout.
		// See the comment in stackCountKey for more details.
		if err := binary.Read(bytes.NewBuffer(keyBytes), p.byteOrder, &key); err != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonKey).Inc()
			return nil, nil, fmt.Errorf("read stack count key: %w", err)
		}

		if key.CustomLabelsID != 0 {
			if _, ok := customLabelsMap[key.CustomLabelsID]; !ok {
				nCustomLabels++
				customLabels := customLabelsArray{}
				customLabelsBytes, err := p.bpfMaps.CustomLabels.GetValue(unsafe.Pointer(&key.CustomLabelsID))
				if err != nil {
					if !warnedOnce {
						level.Warn(p.logger).Log("msg", "Error reading custom labels", "error", err)
					}
					warnedOnce = true
				} else if err := binary.Read(bytes.NewBuffer(customLabelsBytes), p.byteOrder, &customLabels); err != nil {
					if !warnedOnce {
						level.Warn(p.logger).Log("msg", "Error decoding custom labels", "error", err)
					}
					warnedOnce = true
				} else {
					customLabelsMap[key.CustomLabelsID] = customLabels
				}
			}
		}

		// Profile aggregation key.
		pKey := profileKey{pid: key.PID, tid: key.TID, customLabelsID: key.CustomLabelsID}

		// Twice the stack depth because we have a user and a potential Kernel stack.
		// Read order matters, since we read from the key buffer.
		stack := bpfmaps.CombinedStack{}
		interpreterStack := stack[bpfmaps.StackDepth*2:]

		var userErr error

		// User stacks which could have been unwound with the frame pointer or CFI unwinders.
		userStack := stack[:bpfmaps.StackDepth]
		userErr = p.bpfMaps.ReadStack(key.UserStackID, userStack)
		if userErr != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonUser).Inc()
			if errors.Is(userErr, bpfmaps.ErrUnrecoverable) {
				p.metrics.readMapAttempts.WithLabelValues(labelUser, labelNativeUnwind, labelError).Inc()
				return nil, nil, userErr
			}
			if errors.Is(userErr, bpfmaps.ErrUnwindFailed) {
				p.metrics.readMapAttempts.WithLabelValues(labelUser, labelNativeUnwind, labelFailed).Inc()
			}
			if errors.Is(userErr, bpfmaps.ErrMissing) {
				p.metrics.readMapAttempts.WithLabelValues(labelUser, labelNativeUnwind, labelMissing).Inc()
			}
		} else {
			p.metrics.readMapAttempts.WithLabelValues(labelUser, labelNativeUnwind, labelSuccess).Inc()
		}

		if key.InterpreterStackID != 0 {
			if interpErr := p.bpfMaps.ReadStack(key.InterpreterStackID, interpreterStack); interpErr != nil {
				p.metrics.readMapAttempts.WithLabelValues(labelInterpreter, labelInterpreterUnwind, labelError).Inc()
				level.Debug(p.logger).Log("msg", "failed to read interpreter stacks", "err", interpErr)
			} else {
				p.metrics.readMapAttempts.WithLabelValues(labelInterpreter, labelInterpreterUnwind, labelSuccess).Inc()
			}
		}

		kStack := stack[bpfmaps.StackDepth : bpfmaps.StackDepth*2]
		kernelErr := p.bpfMaps.ReadStack(key.KernelStackID, kStack)
		if kernelErr != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonKernel).Inc()
			if errors.Is(kernelErr, bpfmaps.ErrUnrecoverable) {
				p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelError).Inc()
				return nil, nil, kernelErr
			}
			if errors.Is(kernelErr, bpfmaps.ErrUnwindFailed) {
				p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelFailed).Inc()
			}
			if errors.Is(kernelErr, bpfmaps.ErrMissing) {
				p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelMissing).Inc()
			}
		} else {
			p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelSuccess).Inc()
		}

		if userErr != nil && kernelErr != nil && key.InterpreterStackID == 0 {
			// Both user stack (either via frame pointers or dwarf) and kernel stack
			// have failed. Nothing to do.
			continue
		}

		value, err := p.bpfMaps.ReadStackCount(keyBytes)
		if err != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonCount).Inc()
			return nil, nil, fmt.Errorf("read value: %w", err)
		}
		if value == 0 {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonZeroCount).Inc()
			// This should never happen, but it's here just in case.
			// If we have a zero value, we don't want to add it to the profile.
			continue
		}

		perThreadData, ok := rawData[pKey]
		if !ok {
			// We haven't seen this id yet.
			perThreadData = map[bpfmaps.CombinedStack]uint64{}
			rawData[pKey] = perThreadData
		}

		perThreadData[stack] += value
	}
	if warnedOnce {
		level.Info(p.logger).Log("unique custom labels: %d", nCustomLabels)
	}
	if it.Err() != nil {
		p.metrics.stackDrop.WithLabelValues(labelStackDropReasonIterator).Inc()
		return nil, nil, fmt.Errorf("failed iterator: %w", it.Err())
	}

	failedReasons, err := p.bpfMaps.GetUnwindFailedReasons()
	if err != nil {
		return nil, nil, err
	}

	if err := p.bpfMaps.FinalizeProfileLoop(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps that store stacktraces", "err", err)
	}

	return preprocessRawData(rawData, customLabelsMap), failedReasons, nil
}

// preprocessRawData takes the raw data from the BPF maps and converts it into
// a profile.RawData, which already splits the stacks into user, kernel and interpreter
// stacks. Since the input data is a map of maps, we can assume that they're
// already unique and there are no duplicates, which is why at this point we
// can just transform them into plain slices and structs.
func preprocessRawData(rawData map[profileKey]map[bpfmaps.CombinedStack]uint64, customLabelsMap map[uint64]customLabelsArray) profile.RawData {
	res := make(profile.RawData, 0, len(rawData))
	for pKey, perThreadRawData := range rawData {
		p := profile.ProcessRawData{
			PID:        profile.PID(pKey.pid),
			RawSamples: make([]profile.RawSample, 0, len(perThreadRawData)),
		}

		for stack, count := range perThreadRawData {
			kernelStackDepth := 0
			userStackDepth := 0
			interpreterStackDepth := 0

			// We count the number of frames in the stack to be able to preallocate.
			// If the stack frame is the default then the stack ended.
			zero := profile.StackFrame{}
			for _, frame := range stack[:bpfmaps.StackDepth] {
				if frame == zero {
					break
				}
				userStackDepth++
			}
			for _, frame := range stack[bpfmaps.StackDepth : bpfmaps.StackDepth*2] {
				if frame == zero {
					break
				}
				kernelStackDepth++
			}

			for _, frame := range stack[bpfmaps.StackDepth*2:] {
				if frame == zero {
					break
				}
				interpreterStackDepth++
			}

			userStack := make([]profile.StackFrame, userStackDepth)
			kernelStack := make([]profile.StackFrame, kernelStackDepth)
			interpreterStack := make([]profile.StackFrame, interpreterStackDepth)

			copy(userStack, stack[:userStackDepth])
			copy(kernelStack, stack[bpfmaps.StackDepth:bpfmaps.StackDepth+kernelStackDepth])
			copy(interpreterStack, stack[bpfmaps.StackDepth*2:bpfmaps.StackDepth*2+interpreterStackDepth])

			cls := []profile.CustomLabel{}
			if rawCls, ok := customLabelsMap[pKey.customLabelsID]; ok {
				cls = make([]profile.CustomLabel, rawCls.Len)
				for i := 0; i < int(rawCls.Len); i++ {
					cls[i] = profile.CustomLabel{
						Key: string(rawCls.Labels[i].Key[0:(rawCls.Labels[i].KeyLen)]),
						Val: string(rawCls.Labels[i].Val[0:(rawCls.Labels[i].ValLen)]),
					}
				}
			}

			p.RawSamples = append(p.RawSamples, profile.RawSample{
				TID:              profile.PID(pKey.tid),
				UserStack:        userStack,
				KernelStack:      kernelStack,
				InterpreterStack: interpreterStack,
				Value:            count,
				CustomLabels:     cls,
			})
		}

		res = append(res, p)
	}

	return res
}

type errorTracker struct {
	logger          log.Logger
	errorEncounters prometheus.Counter

	name string
	c    *cache.Cache[string, int]
}

func newErrorTracker(logger log.Logger, reg prometheus.Registerer, name string) *errorTracker {
	return &errorTracker{
		name:   name,
		logger: logger,
		errorEncounters: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "parca_agent_profiler_tracked_errors_total",
			Help:        "Counts errors encountered in the profiler",
			ConstLabels: map[string]string{"type": name},
		}),
		c: cache.NewLRUCache[string, int](
			prometheus.WrapRegistererWith(prometheus.Labels{"cache": name}, reg),
			512,
		),
	}
}

func (et *errorTracker) Track(pid int, err error) {
	et.errorEncounters.Inc()
	v, ok := et.c.Peek(err.Error())
	if ok {
		et.c.Add(err.Error(), v+1)
	} else {
		et.c.Add(err.Error(), 1)
	}
	v, _ = et.c.Get(err.Error())
	if v%50 == 0 || v == 1 {
		level.Error(et.logger).Log("msg", "failed to add unwind table due to unavailable .text section", "pid", pid, "err", err, "encounters", v)
	} else {
		level.Debug(et.logger).Log("msg", "failed to add unwind table due to unavailable .text section", "pid", pid, "err", err, "encounters", v)
	}
}
