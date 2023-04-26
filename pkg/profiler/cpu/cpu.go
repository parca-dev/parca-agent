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
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
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
	"github.com/google/pprof/profile"
	"github.com/hashicorp/go-multierror"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/pkg/address"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/stack/unwind"
)

var (
	//go:embed cpu-profiler.bpf.o
	bpfObj []byte

	cpuProgramFd = uint64(0)
)

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in BPF program.
	doubleStackDepth = stackDepth * 2

	programName              = "profile_cpu"
	dwarfUnwinderProgramName = "walk_user_stacktrace_impl"
	configKey                = "unwinder_config"

	kernelMappingFileName = "[kernel.kallsyms]"
)

type Config struct {
	FilterProcesses bool
	VerboseLogging  bool
}

type combinedStack [doubleStackDepth]uint64

type CPU struct {
	logger                     log.Logger
	reg                        prometheus.Registerer
	profilingDuration          time.Duration
	profilingSamplingFrequency uint64

	symbolizer      profiler.Symbolizer
	normalizer      profiler.Normalizer
	processMappings *process.Mapping

	profileWriter    profiler.ProfileWriter
	debuginfoManager profiler.DebugInfoManager
	labelsManager    profiler.LabelsManager

	psMapCache   profiler.ProcessMapCache
	objFileCache profiler.ObjectFileCache

	metrics *metrics

	mtx *sync.RWMutex

	bpfMaps   *bpfMaps
	byteOrder binary.ByteOrder

	// Reporting.
	lastError                      error
	processLastErrors              map[int]error
	lastSuccessfulProfileStartedAt time.Time
	lastProfileStartedAt           time.Time

	memlockRlimit uint64

	debugProcessNames      []string
	isNormalizationEnabled bool
	disableDWARFUnwinding  bool
	verboseBpfLogging      bool

	// Notify that the BPF program was loaded.
	bpfProgramLoaded chan bool

	framePointerCache unwind.FramePointerCache
}

func NewCPUProfiler(
	logger log.Logger,
	reg prometheus.Registerer,
	symbolizer profiler.Symbolizer,
	psMapCache profiler.ProcessMapCache,
	objFileCache profiler.ObjectFileCache,
	profileWriter profiler.ProfileWriter,
	debuginfoProcessor profiler.DebugInfoManager,
	labelsManager profiler.LabelsManager,
	profilingDuration time.Duration,
	profilingSamplingFrequency uint64,
	memlockRlimit uint64,
	debugProcessNames []string,
	enableNormalization bool,
	disableDWARFUnwinding bool,
	verboseBpfLogging bool,
	bpfProgramLoaded chan bool,
) *CPU {
	return &CPU{
		logger: logger,
		reg:    reg,

		symbolizer:       symbolizer,
		profileWriter:    profileWriter,
		debuginfoManager: debuginfoProcessor,
		labelsManager:    labelsManager,
		normalizer:       address.NewNormalizer(logger, objFileCache),
		processMappings:  process.NewMapping(psMapCache),

		// Shared caches between all profilers.
		psMapCache:   psMapCache,
		objFileCache: objFileCache,

		profilingDuration:          profilingDuration,
		profilingSamplingFrequency: profilingSamplingFrequency,

		mtx:       &sync.RWMutex{},
		byteOrder: byteorder.GetHostByteOrder(),
		metrics:   newMetrics(reg),

		memlockRlimit: memlockRlimit,

		debugProcessNames: debugProcessNames,
		// isNormalizationEnabled indicates whether the profiler has to
		// normalize sampled addresses for PIC/PIE (position independent code/executable).
		isNormalizationEnabled: enableNormalization,
		disableDWARFUnwinding:  disableDWARFUnwinding,
		verboseBpfLogging:      verboseBpfLogging,

		bpfProgramLoaded:  bpfProgramLoaded,
		framePointerCache: unwind.NewHasFramePointersCache(logger, reg),
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

func bpfCheck() error {
	var result *multierror.Error

	if support, err := bpf.BPFProgramTypeIsSupported(bpf.BPFProgTypePerfEvent); !support {
		result = multierror.Append(result, fmt.Errorf("perf event program type not supported: %w", err))
	}

	if support, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeStackTrace); !support {
		result = multierror.Append(result, fmt.Errorf("stack trace map type not supported: %w", err))
	}

	if support, err := bpf.BPFMapTypeIsSupported(bpf.MapTypeHash); !support {
		result = multierror.Append(result, fmt.Errorf("hash map type not supported: %w", err))
	}

	return result.ErrorOrNil()
}

func (p *CPU) debugProcesses() bool {
	return len(p.debugProcessNames) > 0
}

// loadBpfProgram loads the BPF program and maps adjusting the unwind shards to
// the highest possible value.
func loadBpfProgram(logger log.Logger, reg prometheus.Registerer, debugEnabled, verboseBpfLogging bool, memlockRlimit uint64) (*bpf.Module, *bpfMaps, error) {
	var (
		m       *bpf.Module
		bpfMaps *bpfMaps
		err     error
	)

	maxLoadAttempts := 10
	unwindShards := uint32(maxUnwindShards)

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(_ int, msg string) {
			level.Debug(logger).Log("msg", msg)
		},
	})

	// Adaptive unwind shard count sizing.
	for i := 0; i < maxLoadAttempts; i++ {
		m, err = bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
			BPFObjBuff: bpfObj,
			BPFObjName: "parca",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("new bpf module: %w", err)
		}

		// Must be called after bpf.NewModuleFromBufferArgs to avoid limit override.
		rLimit, err := profiler.BumpMemlock(memlockRlimit, memlockRlimit)
		if err != nil {
			return nil, nil, fmt.Errorf("bump memlock: %w", err)
		}
		level.Debug(logger).Log("msg", "actual memory locked rlimit", "cur", profiler.HumanizeRLimit(rLimit.Cur), "max", profiler.HumanizeRLimit(rLimit.Max))

		// Maps must be initialized before loading the BPF code.
		bpfMaps, err = initializeMaps(logger, reg, m, binary.LittleEndian)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize eBPF maps: %w", err)
		}

		level.Info(logger).Log("msg", "Attempting to create unwind shards", "count", unwindShards)
		if err := bpfMaps.adjustMapSizes(debugEnabled, unwindShards); err != nil {
			return nil, nil, fmt.Errorf("failed to adjust map sizes: %w", err)
		}

		if err := m.InitGlobalVariable(configKey, Config{FilterProcesses: debugEnabled, VerboseLogging: verboseBpfLogging}); err != nil {
			return nil, nil, fmt.Errorf("init global variable: %w", err)
		}

		err = m.BPFLoadObject()
		if err == nil {
			return m, bpfMaps, nil
		}
		// There's not enough free memory for these many unwind shards, let's retry with half
		// as many.
		if errors.Is(err, syscall.ENOMEM) {
			if err := bpfMaps.close(); err != nil { // Only required when we want to retry.
				return nil, nil, fmt.Errorf("failed to cleanup previously created bpfmaps: %w", err)
			}
			unwindShards /= 2
		} else {
			break
		}
	}
	level.Error(logger).Log("msg", "Could not create unwind info shards")
	return nil, nil, err
}

func (p *CPU) addUnwindTableForProcess(pid int) {
	executable := fmt.Sprintf("/proc/%d/exe", pid)
	hasFramePointers, err := p.framePointerCache.HasFramePointers(executable)
	if err != nil {
		// It might not exist as reading procfs is racy.
		if !errors.Is(err, os.ErrNotExist) {
			level.Error(p.logger).Log("msg", "frame pointer detection failed", "executable", executable, "err", err)
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
		} else {
			level.Error(p.logger).Log("msg", "failed to add unwind table", "pid", pid, "err", err)
		}
		return
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
			// no other dealine in progress. During this time period we'll batch
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

	m, bpfMaps, err := loadBpfProgram(p.logger, p.reg, debugEnabled, p.verboseBpfLogging, p.memlockRlimit)
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
	cpus := runtime.NumCPU()

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

	level.Debug(p.logger).Log("msg", "debug process matchers found, starting process watcher")
	// Update the debug pids map.
	go p.watchProcesses(ctx, pfs, matchers)

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	requestUnwindInfoChannel := make(chan int)
	perfBuf, err := m.InitPerfBuf("events", eventsChannel, lostChannel, 64)
	if err != nil {
		return fmt.Errorf("failed to init perf buffer: %w", err)
	}
	perfBuf.Start()

	// Process BPF events.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case receivedBytes := <-eventsChannel:
				if len(receivedBytes) == 0 {
					continue
				}

				payload := binary.LittleEndian.Uint64(receivedBytes)
				// Get the 4 more significant bytes and convert to int as they are different types.
				// On x86_64:
				//	- unsafe.Sizeof(int(0)) = 8
				//	- unsafe.Sizeof(uint32(0)) = 4
				pid := int(int32(payload))
				//nolint:gocritic
				if payload&RequestUnwindInformation == RequestUnwindInformation {
					requestUnwindInfoChannel <- pid
				} else if payload&RequestProcessMappings == RequestProcessMappings {
					// Populate mappings cache.
					_, _ = p.processMappings.PopulateMappings(pid)
					// TODO: even if we populate the mappings for the process we just got
					// a sample for, we aren't done yet. We also need to extract the debug
					// information so we can symbolize in the server.
					// If the process has exited by the time we call `ObjectFileForProcess`,
					// we might not be able to do it.
					//
					// We could maybe copy the file to tmpfs and then run something like:
					//
					//	```
					//	maps := p.processMappings.MapsForPID(pid)
					//	for _, mf := range maps {
					//		_, _ = p.objFileCache.ObjectFileForProcess(mf.PID, mf.Mapping)
					//	}
					//  ```
				} else if payload&RequestRefreshProcInfo == RequestRefreshProcInfo {
					// Refresh mappings and their unwind info if they've changed.
					//
					// TODO: update the mappings cache above.
					p.bpfMaps.refreshProcessInfo(pid)
				}
			}
		}
	}()

	go func() {
		onDemandUnwindInfoBatcher(ctx, requestUnwindInfoChannel, 150*time.Millisecond, func(pids []int) {
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
	}()

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
		profiles, err := p.obtainProfiles(ctx)
		if err != nil {
			p.metrics.obtainAttempts.WithLabelValues("error").Inc()
			level.Warn(p.logger).Log("msg", "failed to obtain profiles from eBPF maps", "err", err)
			continue
		}
		p.metrics.obtainAttempts.WithLabelValues("success").Inc()
		p.metrics.obtainDuration.Observe(time.Since(obtainStart).Seconds())

		processLastErrors := map[int]error{}

		var objFiles []*objectfile.MappedObjectFile
		for _, prof := range profiles {
			start := time.Now()
			processLastErrors[int(prof.ID.PID)] = nil

			if err := p.symbolizer.Symbolize(prof); err != nil {
				// This could be a partial symbolization, so we still want to send the profile.
				level.Debug(p.logger).Log("msg", "failed to symbolize profile", "pid", prof.ID.PID, "err", err)
				processLastErrors[int(prof.ID.PID)] = err
			}

			// ConvertToPprof can combine multiple profiles into a single profile,
			// however right now we chose to send each profile separately.
			// This is not too inefficient as we batch the profiles in a single RPC message,
			// using the batch profiler writer.
			pprof, err := profiler.ConvertToPprof(p.LastProfileStartedAt(), samplingPeriod, prof)
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to convert profile to pprof", "pid", prof.ID.PID, "err", err)
				processLastErrors[int(prof.ID.PID)] = err
				continue
			}

			labelSet := p.labelsManager.LabelSet(p.Name(), uint64(prof.ID.PID))
			if labelSet == nil {
				level.Debug(p.logger).Log("msg", "profile dropped", "pid", prof.ID.PID)
				continue
			}

			p.metrics.symbolizeDuration.Observe(time.Since(start).Seconds())

			if err := p.profileWriter.Write(ctx, labelSet, pprof); err != nil {
				level.Warn(p.logger).Log("msg", "failed to write profile", "pid", prof.ID.PID, "err", err)
				processLastErrors[int(prof.ID.PID)] = err
				continue
			}
			if p.debuginfoManager != nil {
				maps := p.processMappings.MapsForPID(int(prof.ID.PID))
				for _, mf := range maps {
					objFile, err := p.objFileCache.ObjectFileForProcess(mf.PID, mf.Mapping)
					if err != nil {
						processLastErrors[int(prof.ID.PID)] = err
						continue
					}
					objFiles = append(objFiles, objFile)
				}
			}
		}
		// Upload debug information of the discovered object files.
		p.debuginfoManager.EnsureUploaded(ctx, objFiles)

		p.report(err, processLastErrors)
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
		if p.debugProcesses() {
			for _, thread := range allThreads() {
				comm, err := thread.Comm()
				if err != nil {
					level.Debug(p.logger).Log("msg", "failed to read process name", "err", err)
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
		TGID             int32
		UserStackID      int32
		KernelStackID    int32
		UserStackIDDWARF int32
	}
)

func (s *stackCountKey) walkedWithDwarf() bool {
	return s.UserStackIDDWARF != 0
}

const (
	labelUser         = "user"
	labelKernel       = "kernel"
	labelKernelUnwind = "kernel_unwind"
	labelDwarfUnwind  = "dwarf_unwind"
	labelError        = "error"
	labelMissing      = "missing"
	labelFailed       = "failed"
	labelSuccess      = "success"
)

// obtainProfiles collects profiles from the BPF maps.
func (p *CPU) obtainProfiles(ctx context.Context) ([]*profiler.Profile, error) {
	var (
		kernelMapping = &profile.Mapping{
			File: kernelMappingFileName,
		}
		// All these are grouped by the group key, which happens to be a pid right now.
		allSamples      = map[profiler.StackID]map[combinedStack]*profile.Sample{}
		sampleLocations = map[profiler.StackID][]*profile.Location{}
		locations       = map[profiler.StackID][]*profile.Location{}
		kernelLocations = map[profiler.StackID][]*profile.Location{}
		userLocations   = map[profiler.StackID][]*profile.Location{}
		locationIndices = map[profiler.StackID]map[uint64]int{}
	)

	it := p.bpfMaps.stackCounts.Iterator()
	for it.Next() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// This byte slice is only valid for this iteration, so it must be
		// copied if we want to do anything with it outside this loop.
		keyBytes := it.Key()

		var key stackCountKey
		// NOTICE: This works because the key struct in Go and the key struct in C has exactly the same memory layout.
		// See the comment in stackCountKey for more details.
		if err := binary.Read(bytes.NewBuffer(keyBytes), p.byteOrder, &key); err != nil {
			return nil, fmt.Errorf("read stack count key: %w", err)
		}

		id := profiler.StackID{PID: profiler.PID(key.PID), TGID: profiler.PID(key.TGID)}

		// Twice the stack depth because we have a user and a potential Kernel stack.
		// Read order matters, since we read from the key buffer.
		stack := combinedStack{}

		var userErr error
		if key.walkedWithDwarf() {
			// Stacks retrieved with our dwarf unwind information unwinder.
			userErr = p.bpfMaps.readUserStackWithDwarf(key.UserStackIDDWARF, &stack)
			if userErr != nil {
				if errors.Is(userErr, errUnrecoverable) {
					p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelError).Inc()
					return nil, userErr
				}
				if errors.Is(userErr, errUnwindFailed) {
					p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelFailed).Inc()
				}
				if errors.Is(userErr, errMissing) {
					p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelMissing).Inc()
				}
				p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelDwarfUnwind, labelSuccess).Inc()
				continue
			}
		} else {
			// Stacks retrieved with the kernel's included frame pointer based unwinder.
			userErr = p.bpfMaps.readUserStack(key.UserStackID, &stack)
			if userErr != nil {
				if errors.Is(userErr, errUnrecoverable) {
					p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelError).Inc()
					return nil, userErr
				}
				if errors.Is(userErr, errUnwindFailed) {
					p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelFailed).Inc()
				}
				if errors.Is(userErr, errMissing) {
					p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelMissing).Inc()
				}
				continue
			}
			p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelSuccess).Inc()
		}
		kernelErr := p.bpfMaps.readKernelStack(key.KernelStackID, &stack)
		if kernelErr != nil {
			if errors.Is(kernelErr, errUnrecoverable) {
				p.metrics.obtainMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelError).Inc()
				return nil, kernelErr
			}
			if errors.Is(kernelErr, errUnwindFailed) {
				p.metrics.obtainMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelFailed).Inc()
			}
			if errors.Is(kernelErr, errMissing) {
				p.metrics.obtainMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelMissing).Inc()
			}
		}
		p.metrics.obtainMapAttempts.WithLabelValues(labelKernel, labelKernelUnwind, labelSuccess).Inc()

		if userErr != nil && !key.walkedWithDwarf() && kernelErr != nil {
			// Both user stack (either via frame pointers or dwarf) and kernel stack
			// have failed. Nothing to do.
			continue
		}

		value, err := p.bpfMaps.readStackCount(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("read value: %w", err)
		}
		if value == 0 {
			// This should never happen, but it's here just in case.
			// If we have a zero value, we don't want to add it to the profile.
			continue
		}

		_, ok := allSamples[id]
		if !ok {
			// We haven't seen this id yet.
			allSamples[id] = map[combinedStack]*profile.Sample{}
		}

		sample, ok := allSamples[id][stack]
		if ok {
			// We already have a sample with this stack trace, so just add
			// it to the previous one.
			sample.Value[0] += int64(value)
			continue
		}

		sampleLocations[id] = []*profile.Location{}

		_, ok = userLocations[id]
		if !ok {
			userLocations[id] = []*profile.Location{}
		}
		_, ok = locationIndices[id]
		if !ok {
			locationIndices[id] = map[uint64]int{}
		}

		// Collect Kernel stack trace samples.
		for _, addr := range stack[stackDepth:] {
			if addr != uint64(0) {
				locationIndex, ok := locationIndices[id][addr]
				if !ok {
					locationIndex = len(locations[id])
					l := &profile.Location{
						ID:      uint64(locationIndex + 1),
						Address: addr,
						Mapping: kernelMapping,
					}
					locations[id] = append(locations[id], l)
					kernelLocations[id] = append(kernelLocations[id], l)
					locationIndices[id][addr] = locationIndex
				}
				sampleLocations[id] = append(
					sampleLocations[id],
					locations[id][locationIndex],
				)
			}
		}

		normalizationFailure := false

		// Collect User stack trace samples.
		for _, addr := range stack[:stackDepth] {
			if addr != uint64(0) {
				locationIndex, ok := locationIndices[id][addr]
				if !ok {
					locationIndex = len(locations[id])

					m, err := p.processMappings.PIDAddrMapping(int(key.PID), addr)
					if err != nil {
						if !errors.Is(err, process.ErrNotFound) {
							level.Debug(p.logger).Log("msg", "failed to get process mapping", "pid", id.PID, "address", addr, "err", err)
						}
					}

					l := &profile.Location{
						ID:      uint64(locationIndex + 1),
						Address: addr,
						Mapping: m,
					}

					if p.isNormalizationEnabled {
						normalizedAddress, err := p.normalizer.Normalize(int(key.PID), m, addr)
						if err != nil {
							normalizationFailure = true
							level.Debug(p.logger).Log("msg", "failed to normalize address", "pid", id.PID, "address", fmt.Sprintf("%x", addr), "err", err)
							break
						}

						l.Address = normalizedAddress
					}

					locations[id] = append(locations[id], l)
					userLocations[id] = append(userLocations[id], l)
					locationIndices[id][addr] = locationIndex
				}
				sampleLocations[id] = append(
					sampleLocations[id],
					locations[id][locationIndex],
				)
			}
		}

		if p.isNormalizationEnabled {
			if normalizationFailure {
				p.metrics.normalizationAttempts.WithLabelValues("error").Inc()
				// Drop stack if a frame failed to normalize.
				continue
			} else {
				p.metrics.normalizationAttempts.WithLabelValues("success").Inc()
			}
		}

		sample = &profile.Sample{
			Value:    []int64{int64(value)},
			Location: sampleLocations[id],
		}
		allSamples[id][stack] = sample
	}
	if it.Err() != nil {
		return nil, fmt.Errorf("failed iterator: %w", it.Err())
	}

	if err := p.bpfMaps.finalizeProfileLoop(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps that store stacktraces", "err", err)
	}

	profiles := []*profiler.Profile{}
	for id, stackSamples := range allSamples {
		samples := make([]*profile.Sample, 0, len(stackSamples))
		for _, s := range stackSamples {
			samples = append(samples, s)
		}
		profiles = append(profiles, &profiler.Profile{
			ID:              id,
			Samples:         samples,
			Locations:       locations[id],
			KernelLocations: kernelLocations[id],
			UserLocations:   userLocations[id],
			UserMappings:    p.processMappings.MappingsForPID(int(id.PID)),
			KernelMapping:   kernelMapping,
		})
	}
	return profiles, nil
}
