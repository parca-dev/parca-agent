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

package cpu

import "C" //nolint:all

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/puzpuzpuz/xsync/v2"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/cache"
	"github.com/parca-dev/parca-agent/pkg/cpuinfo"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/pprof"
	"github.com/parca-dev/parca-agent/pkg/profile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/rlimit"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

var (
	//go:embed bpf/*
	bpfObjects embed.FS

	cpuProgramFd = uint64(0)
)

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in BPF program.
	doubleStackDepth = stackDepth * 2

	programName              = "profile_cpu"
	dwarfUnwinderProgramName = "walk_user_stacktrace_impl"
	configKey                = "unwinder_config"
)

type Config struct {
	FilterProcesses   bool
	VerboseLogging    bool
	MixedStackWalking bool
}

type combinedStack [doubleStackDepth]uint64

type CPU struct {
	logger  log.Logger
	reg     prometheus.Registerer
	metrics *metrics

	mtx *sync.RWMutex

	profilingDuration          time.Duration
	profilingSamplingFrequency uint64

	perfEventBufferPollInterval       time.Duration
	perfEventBufferProcessingInterval time.Duration
	perfEventBufferWorkerCount        int

	processInfoManager profiler.ProcessInfoManager
	profileConverter   *pprof.Manager
	profileStore       profiler.ProfileStore

	framePointerCache unwind.FramePointerCache

	bpfMaps   *bpfMaps
	byteOrder binary.ByteOrder

	lastError                      error
	processLastErrors              map[int]error
	processErrorTracker            *cache.LRUCache[string, int]
	lastSuccessfulProfileStartedAt time.Time
	lastProfileStartedAt           time.Time

	debugProcessNames     []string
	dwarfUnwindingDisable bool

	memlockRlimit     uint64
	bpfLoggingVerbose bool

	mixedUnwinding    bool
	verboseBpfLogging bool

	// Notify that the BPF program was loaded.
	bpfProgramLoaded chan bool
}

func NewCPUProfiler(
	logger log.Logger,
	reg prometheus.Registerer,
	processInfoManager profiler.ProcessInfoManager,
	profileConverter *pprof.Manager,
	profileWriter profiler.ProfileStore,
	profilingDuration time.Duration,
	profilingSamplingFrequency uint64,
	perfEventBufferPollInterval time.Duration,
	perfEventBufferProcessingInterval time.Duration,
	perfEventBufferWorkerCount int,
	memlockRlimit uint64,
	debugProcessNames []string,
	disableDWARFUnwinding bool,
	mixedUnwinding bool,
	verboseBpfLogging bool,
	bpfProgramLoaded chan bool,
) *CPU {
	return &CPU{
		logger: logger,
		reg:    reg,

		processInfoManager: processInfoManager,
		profileConverter:   profileConverter,
		profileStore:       profileWriter,

		// CPU profiler specific caches.
		framePointerCache: unwind.NewHasFramePointersCache(logger, reg),

		profilingDuration:          profilingDuration,
		profilingSamplingFrequency: profilingSamplingFrequency,

		perfEventBufferPollInterval:       perfEventBufferPollInterval,
		perfEventBufferProcessingInterval: perfEventBufferProcessingInterval,
		perfEventBufferWorkerCount:        perfEventBufferWorkerCount,

		mtx:       &sync.RWMutex{},
		byteOrder: byteorder.GetHostByteOrder(),
		metrics:   newMetrics(reg),

		memlockRlimit: memlockRlimit,

		// increase cache length if needed to track more errors
		processErrorTracker: cache.NewLRUCache[string, int](prometheus.WrapRegistererWith(prometheus.Labels{"cache": "no_text_section_error_tracker"}, reg), 512),

		debugProcessNames: debugProcessNames,

		dwarfUnwindingDisable: disableDWARFUnwinding,
		mixedUnwinding:        mixedUnwinding,
		bpfLoggingVerbose:     verboseBpfLogging,

		bpfProgramLoaded: bpfProgramLoaded,
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

func (p *CPU) debugProcesses() bool {
	return len(p.debugProcessNames) > 0
}

// loadBpfProgram loads the BPF program and maps adjusting the unwind shards to
// the highest possible value.
func loadBpfProgram(logger log.Logger, reg prometheus.Registerer, mixedUnwinding, debugEnabled, dwarfUnwindDisabled, verboseBpfLogging bool, memlockRlimit uint64) (*bpf.Module, *bpfMaps, error) {
	var lerr error

	maxLoadAttempts := 10
	unwindShards := uint32(maxUnwindShards)

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(_ int, msg string) {
			level.Debug(logger).Log("msg", msg)
		},
	})

	f, err := bpfObjects.Open(fmt.Sprintf("bpf/%s/cpu.bpf.o", runtime.GOARCH))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open BPF object: %w", err)
	}
	// Note: no need to close this file, it's a virtual file from embed.FS, for
	// which Close is a no-op.

	bpfObj, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read BPF object: %w", err)
	}

	// Adaptive unwind shard count sizing.
	for i := 0; i < maxLoadAttempts; i++ {
		m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
			BPFObjBuff: bpfObj,
			BPFObjName: "parca",
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

		// Maps must be initialized before loading the BPF code.
		bpfMaps, err := initializeMaps(logger, reg, m, binary.LittleEndian)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize eBPF maps: %w", err)
		}

		if dwarfUnwindDisabled {
			// Even if DWARF-based unwinding is disabled, either due to the user passing the flag to disable it or running on arm64, still
			// create a handful of shards to ensure that when it is enabled we can at least create some shards. Basically we want to ensure
			// that we catch any potential issues as early as possible.
			unwindShards = uint32(5)
		}

		level.Info(logger).Log("msg", "Attempting to create unwind shards", "count", unwindShards)
		if err := bpfMaps.adjustMapSizes(debugEnabled, unwindShards); err != nil {
			return nil, nil, fmt.Errorf("failed to adjust map sizes: %w", err)
		}

		if err := m.InitGlobalVariable(configKey, Config{FilterProcesses: debugEnabled, VerboseLogging: verboseBpfLogging, MixedStackWalking: mixedUnwinding}); err != nil {
			return nil, nil, fmt.Errorf("init global variable: %w", err)
		}

		lerr = m.BPFLoadObject()
		if lerr == nil {
			return m, bpfMaps, nil
		}
		// There's not enough free memory for these many unwind shards, let's retry with half
		// as many.
		if errors.Is(lerr, syscall.ENOMEM) {
			if err := bpfMaps.close(); err != nil { // Only required when we want to retry.
				return nil, nil, fmt.Errorf("failed to cleanup previously created bpfmaps: %w", err)
			}
			unwindShards /= 2
		} else {
			break
		}
	}
	level.Error(logger).Log("msg", "Could not create unwind info shards", "lastError", lerr)
	return nil, nil, lerr
}

func (p *CPU) addUnwindTableForProcess(pid int) {
	executable := fmt.Sprintf("/proc/%d/exe", pid)
	hasFramePointers, err := p.framePointerCache.HasFramePointers(executable)
	if err != nil {
		// It might not exist as reading procfs is racy.
		if !errors.Is(err, os.ErrNotExist) {
			level.Debug(p.logger).Log("msg", "frame pointer detection failed", "executable", executable, "err", err)
		}
		return
	}

	if hasFramePointers {
		return
	}

	level.Debug(p.logger).Log("msg", "adding unwind tables", "pid", pid)

	err = p.bpfMaps.addUnwindTableForProcess(pid, nil, true)
	if err != nil {
		//nolint: gocritic
		if errors.Is(err, ErrNeedMoreProfilingRounds) {
			level.Debug(p.logger).Log("msg", "PersistUnwindTable called to soon", "err", err)
		} else if errors.Is(err, os.ErrNotExist) {
			level.Debug(p.logger).Log("msg", "failed to add unwind table due to a procfs race", "pid", pid, "err", err)
		} else if errors.Is(err, errTooManyExecutableMappings) {
			level.Warn(p.logger).Log("msg", "failed to add unwind table due to having too many executable mappings", "pid", pid, "err", err)
		} else if errors.Is(err, buildid.ErrTextSectionNotFound) {
			v, ok := p.processErrorTracker.Peek(err.Error())
			if ok {
				p.processErrorTracker.Add(err.Error(), v+1)
			} else {
				p.processErrorTracker.Add(err.Error(), 1)
			}
			v, _ = p.processErrorTracker.Get(err.Error())
			if v%50 == 0 || v == 1 {
				level.Error(p.logger).Log("msg", "failed to add unwind table due to unavailable .text section", "pid", pid, "err", err, "encounters", v)
			} else {
				level.Debug(p.logger).Log("msg", "failed to add unwind table due to unavailable .text section", "pid", pid, "err", err, "encounters", v)
			}
		} else {
			level.Error(p.logger).Log("msg", "failed to add unwind table", "pid", pid, "err", err)
		}
		return
	}
}

func (p *CPU) prefetchProcessInfo(ctx context.Context, pid int) {
	if _, err := p.processInfoManager.Fetch(ctx, pid); err != nil {
		level.Debug(p.logger).Log("msg", "failed to prefetch process info", "pid", pid, "err", err)
	}
}

// listenEvents listens for events from the BPF program and handles them.
// It also listens for lost events and logs them.
func (p *CPU) listenEvents(ctx context.Context, eventsChan <-chan []byte, lostChan <-chan uint64, requestUnwindInfoChan chan<- int) {
	prefetch := make(chan int, p.perfEventBufferWorkerCount*4)
	refresh := make(chan int, p.perfEventBufferWorkerCount*2)
	defer func() {
		close(prefetch)
		close(refresh)
	}()

	var (
		fetchInProgress   = xsync.NewIntegerMapOf[int, struct{}]()
		refreshInProgress = xsync.NewIntegerMapOf[int, struct{}]()
	)
	for i := 0; i < p.perfEventBufferWorkerCount; i++ {
		go func() {
			for {
				select {
				case pid, open := <-prefetch:
					if !open {
						return
					}
					p.prefetchProcessInfo(ctx, pid)
					fetchInProgress.Delete(pid)
				case pid, open := <-refresh:
					if !open {
						return
					}
					p.bpfMaps.refreshProcessInfo(pid)
					refreshInProgress.Delete(pid)
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
				continue
			}

			payload := binary.LittleEndian.Uint64(receivedBytes)
			// Get the 4 more significant bytes and convert to int as they are different types.
			// On x86_64:
			//	- unsafe.Sizeof(int(0)) = 8
			//	- unsafe.Sizeof(uint32(0)) = 4
			pid := int(int32(payload))
			switch {
			case payload&RequestUnwindInformation == RequestUnwindInformation:
				if p.dwarfUnwindingDisable {
					continue
				}
				// See onDemandUnwindInfoBatcher for consumer.
				requestUnwindInfoChan <- pid
			case payload&RequestProcessMappings == RequestProcessMappings:
				if _, exists := fetchInProgress.LoadOrStore(pid, struct{}{}); exists {
					continue
				}
				prefetch <- pid
			case payload&RequestRefreshProcInfo == RequestRefreshProcInfo:
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
			level.Warn(p.logger).Log("msg", "lost events", "count", lost)
		default:
			time.Sleep(p.perfEventBufferProcessingInterval)
		}
	}
}

// onDemandUnwindInfoBatcher batches PIDs sent from the BPF program when
// frame pointers and unwind information are not present.
//
// Waiting for as long as `duration` is important because `PersistUnwindTable`
// must be called to write the in-flight shard to the BPF map. This has been
// a hot path in the CPU profiles we take in Demo when we persisted the unwind
// tables after adding every pid.
func onDemandUnwindInfoBatcher(ctx context.Context, eventsChannel <-chan int, duration time.Duration, callback func([]int)) {
	batch := make([]int, 0)
	timerOn := false
	timer := &time.Timer{}
	for {
		select {
		case <-ctx.Done():
			return
		case pid := <-eventsChannel:
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
			callback(batch)
			batch = batch[:0]
			timerOn = false
			timer.Stop()
		}
	}
}

func bpfCheck() error {
	var result error

	if support, err := bpf.BPFProgramTypeIsSupported(bpf.BPFProgTypePerfEvent); !support {
		result = errors.Join(result, fmt.Errorf("perf event program type not supported: %w", err))
	}

	if support, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeStackTrace); !support {
		result = errors.Join(result, fmt.Errorf("stack trace map type not supported: %w", err))
	}

	if support, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeHash); !support {
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
	if p.debugProcesses() {
		level.Info(p.logger).Log("msg", "process names specified, debugging processes", "matchers", strings.Join(p.debugProcessNames, ", "))
		for _, exp := range p.debugProcessNames {
			regex, err := regexp.Compile(exp)
			if err != nil {
				return fmt.Errorf("failed to compile regex: %w", err)
			}
			matchers = append(matchers, regex)
		}
	}

	debugEnabled := len(matchers) > 0

	m, bpfMaps, err := loadBpfProgram(p.logger, p.reg, p.mixedUnwinding, debugEnabled, p.dwarfUnwindingDisable, p.bpfLoggingVerbose, p.memlockRlimit)
	if err != nil {
		return fmt.Errorf("load bpf program: %w", err)
	}
	defer m.Close()

	p.bpfProgramLoaded <- true
	p.bpfMaps = bpfMaps

	// Get bpf metrics
	agentProc, err := procfs.Self() // pid of parca-agent
	if err != nil {
		level.Debug(p.logger).Log("msg", "error getting parca-agent pid", "err", err)
	}

	p.reg.MustRegister(newBPFMetricsCollector(p, m, agentProc.PID))

	// Period is the number of events between sampled occurrences.
	// By default we sample at 19Hz (19 times per second),
	// which is every ~0.05s or 52,631,578 nanoseconds (1 Hz = 1e9 ns).
	samplingPeriod := int64(1e9 / p.profilingSamplingFrequency)
	cpus := cpuinfo.NumCPU()

	for i := 0; i < cpus; i++ {
		fd, err := unix.PerfEventOpen(&unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: p.profilingSamplingFrequency,
			Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		}, -1 /* pid */, i /* cpu id */, -1 /* group */, 0 /* flags */)
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

		prog, err := m.GetProgram(programName)
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

	// Record start time for first profile.
	p.mtx.Lock()
	p.lastProfileStartedAt = time.Now()
	p.mtx.Unlock()

	prog, err := m.GetProgram(dwarfUnwinderProgramName)
	if err != nil {
		return fmt.Errorf("get bpf program: %w", err)
	}
	programs, err := m.GetMap(programsMapName)
	if err != nil {
		return fmt.Errorf("get programs map: %w", err)
	}

	fd := prog.FileDescriptor()
	if err := programs.Update(unsafe.Pointer(&cpuProgramFd), unsafe.Pointer(&fd)); err != nil {
		return fmt.Errorf("failure updating: %w", err)
	}

	if err := p.bpfMaps.create(); err != nil {
		return fmt.Errorf("failed to create maps: %w", err)
	}

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return fmt.Errorf("failed to create procfs: %w", err)
	}

	// Update the debug pids map.
	go p.watchProcesses(ctx, pfs, matchers)

	// Process BPF events.
	var (
		eventsChan               = make(chan []byte)
		lostChannel              = make(chan uint64)
		requestUnwindInfoChannel = make(chan int)
	)
	perfBuf, err := m.InitPerfBuf("events", eventsChan, lostChannel, 64)
	if err != nil {
		return fmt.Errorf("failed to init perf buffer: %w", err)
	}
	perfBuf.Poll(int(p.perfEventBufferPollInterval.Milliseconds()))
	go p.listenEvents(ctx, eventsChan, lostChannel, requestUnwindInfoChannel)

	go onDemandUnwindInfoBatcher(ctx, requestUnwindInfoChannel, 150*time.Millisecond, func(pids []int) {
		for _, pid := range pids {
			p.addUnwindTableForProcess(pid)
		}

		// Must be called after all the calls to `addUnwindTableForProcess`, as it's possible
		// that the current in-flight shard hasn't been written to the BPF map, yet.
		err := p.bpfMaps.PersistUnwindTable()
		if err != nil {
			if errors.Is(err, ErrNeedMoreProfilingRounds) {
				level.Debug(p.logger).Log("msg", "PersistUnwindTable called to soon", "err", err)
			} else {
				level.Error(p.logger).Log("msg", "PersistUnwindTable failed", "err", err)
			}
		}
	})

	ticker := time.NewTicker(p.profilingDuration)
	defer ticker.Stop()

	level.Debug(p.logger).Log("msg", "start profiling loop")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		obtainStart := time.Now()
		rawData, err := p.obtainRawData(ctx)
		if err != nil {
			p.metrics.obtainAttempts.WithLabelValues(labelError).Inc()
			level.Warn(p.logger).Log("msg", "failed to obtain profiles from eBPF maps", "err", err)
			continue
		}
		p.metrics.obtainAttempts.WithLabelValues(labelSuccess).Inc()
		p.metrics.obtainDuration.Observe(time.Since(obtainStart).Seconds())

		groupedRawData := make(map[int]profile.ProcessRawData)
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
				p.metrics.profileDrop.WithLabelValues(profileDropReasonProcessInfo).Inc()
				level.Debug(p.logger).Log("msg", "failed to get process info", "pid", pid, "err", err)
				processLastErrors[pid] = err
				continue
			}

			pprof, executableInfos, err := p.profileConverter.NewConverter(
				pfs,
				pid,
				pi.Mappings.ExecutableSections(),
				p.LastProfileStartedAt(),
				samplingPeriod,
			).Convert(ctx, perProcessRawData.RawSamples)
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to convert profile to pprof", "pid", pid, "err", err)
				processLastErrors[pid] = err
				continue
			}

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
		p.report(err, processLastErrors)
	}
}

// TODO(kakkoyun): Combine with process information discovery.
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
		if p.debugProcesses() {
			level.Debug(p.logger).Log("msg", "debug process matchers found, starting process watcher")

			for _, thread := range allThreads() {
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
				if err := p.bpfMaps.setDebugPIDs(pids); err != nil {
					level.Error(p.logger).Log("msg", "failed to update debug pids map", "err", err)
				}
			} else {
				level.Debug(p.logger).Log("msg", "no processes matched the provided regex")
				if err := p.bpfMaps.setDebugPIDs(nil); err != nil {
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

func (p *CPU) report(lastError error, processLastErrors map[int]error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if lastError == nil {
		p.lastSuccessfulProfileStartedAt = p.lastProfileStartedAt
		p.lastProfileStartedAt = time.Now()
	}
	p.lastError = lastError
	p.processLastErrors = processLastErrors
}

type (
	// stackCountKey mirrors the struct in BPF program.
	// NOTICE: The memory layout and alignment of the struct currently matches the struct in BPF program.
	// However, keep in mind that Go compiler injects padding to align the struct fields to be a multiple of 8 bytes.
	// The Go spec says the address of a struct’s fields must be naturally aligned.
	// https://dave.cheney.net/2015/10/09/padding-is-hard
	// TODO(https://github.com/parca-dev/parca-agent/issues/207)
	stackCountKey struct {
		PID              int32
		TID              int32
		UserStackID      int32
		KernelStackID    int32
		UserStackIDDWARF int32
	}
)

func (s *stackCountKey) walkedWithDwarf() bool {
	return s.UserStackIDDWARF != 0
}

type profileKey struct {
	pid int32
	tid int32
}

// obtainProfiles collects profiles from the BPF maps.
func (p *CPU) obtainRawData(ctx context.Context) (profile.RawData, error) {
	rawData := map[profileKey]map[combinedStack]uint64{}

	it := p.bpfMaps.stackCounts.Iterator()
	for it.Next() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// This byte slice is only valid for this iteration, so it must be
		// copied if we want to do anything with it outside this loop.
		keyBytes := it.Key()

		var key stackCountKey
		// NOTICE: This works because the key struct in Go and the key struct in C has exactly the same memory layout.
		// See the comment in stackCountKey for more details.
		if err := binary.Read(bytes.NewBuffer(keyBytes), p.byteOrder, &key); err != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonKey).Inc()
			return nil, fmt.Errorf("read stack count key: %w", err)
		}

		// Profile aggregation key.
		pKey := profileKey{pid: key.PID, tid: key.TID}

		// Twice the stack depth because we have a user and a potential Kernel stack.
		// Read order matters, since we read from the key buffer.
		stack := combinedStack{}

		var userErr error
		if key.walkedWithDwarf() {
			// Stacks retrieved with our dwarf unwind information unwinder.
			userErr = p.bpfMaps.readUserStackWithDwarf(key.UserStackIDDWARF, &stack)
			if userErr != nil {
				p.metrics.stackDrop.WithLabelValues(labelStackDropReasonUserDWARF).Inc()
				if errors.Is(userErr, errUnrecoverable) {
					p.metrics.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelError).Inc()
					return nil, userErr
				}
				if errors.Is(userErr, errUnwindFailed) {
					p.metrics.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelFailed).Inc()
				}
				if errors.Is(userErr, errMissing) {
					p.metrics.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelMissing).Inc()
				}
			} else {
				p.metrics.readMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelSuccess).Inc()
			}
		} else {
			// Stacks retrieved with the kernel's included frame pointer based unwinder.
			userErr = p.bpfMaps.readUserStack(key.UserStackID, &stack)
			if userErr != nil {
				p.metrics.stackDrop.WithLabelValues(labelStackDropReasonUserFramePointer).Inc()
				if errors.Is(userErr, errUnrecoverable) {
					p.metrics.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelError).Inc()
					return nil, userErr
				}
				if errors.Is(userErr, errUnwindFailed) {
					p.metrics.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelFailed).Inc()
				}
				if errors.Is(userErr, errMissing) {
					p.metrics.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelMissing).Inc()
				}
			} else {
				p.metrics.readMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelSuccess).Inc()
			}
		}

		kernelErr := p.bpfMaps.readKernelStack(key.KernelStackID, &stack)
		if kernelErr != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonKernel).Inc()
			if errors.Is(kernelErr, errUnrecoverable) {
				p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelError).Inc()
				return nil, kernelErr
			}
			if errors.Is(kernelErr, errUnwindFailed) {
				p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelFailed).Inc()
			}
			if errors.Is(kernelErr, errMissing) {
				p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelMissing).Inc()
			}
		} else {
			p.metrics.readMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelSuccess).Inc()
		}

		if userErr != nil && kernelErr != nil {
			// Both user stack (either via frame pointers or dwarf) and kernel stack
			// have failed. Nothing to do.
			continue
		}

		value, err := p.bpfMaps.readStackCount(keyBytes)
		if err != nil {
			p.metrics.stackDrop.WithLabelValues(labelStackDropReasonCount).Inc()
			return nil, fmt.Errorf("read value: %w", err)
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
			perThreadData = map[combinedStack]uint64{}
			rawData[pKey] = perThreadData
		}

		perThreadData[stack] += value
	}
	if it.Err() != nil {
		p.metrics.stackDrop.WithLabelValues(labelStackDropReasonIterator).Inc()
		return nil, fmt.Errorf("failed iterator: %w", it.Err())
	}

	if err := p.bpfMaps.finalizeProfileLoop(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps that store stacktraces", "err", err)
	}

	return preprocessRawData(rawData), nil
}

// preprocessRawData takes the raw data from the BPF maps and converts it into
// a profile.RawData, which already splits the stacks into user and kernel
// stacks. Since the input data is a map of maps, we can assume that they're
// already unique and there are no duplicates, which is why at this point we
// can just transform them into plain slices and structs.
func preprocessRawData(rawData map[profileKey]map[combinedStack]uint64) profile.RawData {
	res := make(profile.RawData, 0, len(rawData))
	for pKey, perThreadRawData := range rawData {
		p := profile.ProcessRawData{
			PID:        profile.PID(pKey.pid),
			RawSamples: make([]profile.RawSample, 0, len(perThreadRawData)),
		}

		for stack, count := range perThreadRawData {
			kernelStackDepth := 0
			userStackDepth := 0

			// We count the number of kernel and user frames in the stack to be
			// able to preallocate. If an address in the stack is 0 then the
			// stack ended.
			for _, addr := range stack[:stackDepth] {
				if addr != 0 {
					userStackDepth++
				}
			}
			for _, addr := range stack[stackDepth:] {
				if addr != 0 {
					kernelStackDepth++
				}
			}

			userStack := make([]uint64, userStackDepth)
			kernelStack := make([]uint64, kernelStackDepth)

			copy(userStack, stack[:userStackDepth])
			copy(kernelStack, stack[stackDepth:stackDepth+kernelStackDepth])

			p.RawSamples = append(p.RawSamples, profile.RawSample{
				TID:         profile.PID(pKey.tid),
				UserStack:   userStack,
				KernelStack: kernelStack,
				Value:       count,
			})
		}

		res = append(res, p)
	}

	return res
}
