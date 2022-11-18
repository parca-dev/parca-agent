// Copyright 2022 The Parca Authors
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
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/dustin/go-humanize"
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

//go:embed cpu-profiler.bpf.o
var bpfObj []byte

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in BPF program.
	doubleStackDepth = stackDepth * 2

	programName              = "profile_cpu"
	dwarfUnwinderProgramName = "walk_user_stacktrace_impl"
	configKey                = "config"

	kernelMappingFileName = "[kernel.kallsyms]"
)

type Config struct {
	Debug bool
}

type separateStack [stackDepth]uint64
type combinedStack [doubleStackDepth]uint64

type CPU struct {
	logger            log.Logger
	profilingDuration time.Duration

	symbolizer      profiler.Symbolizer
	normalizer      profiler.Normalizer
	processMappings *process.Mapping

	profileWriter    profiler.ProfileWriter
	debuginfoManager profiler.DebugInfoManager
	labelsManager    profiler.LabelsManager

	seenKernelStackIDFP  map[int32]separateStack
	seenUserStackIDFP    map[int32]separateStack
	seenUserStackIDDWARF map[int32]separateStack
	psMapCache           profiler.ProcessMapCache
	objFileCache         profiler.ObjectFileCache
	unwindTableBuilder   *unwind.UnwindTableBuilder

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

	debugProcessNames    []string
	enableDWARFUnwinding bool
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
	memlockRlimit uint64,
	debugProcessNames []string,
	enableDWARFUnwinding bool,
) *CPU {
	return &CPU{
		logger: logger,

		symbolizer:       symbolizer,
		profileWriter:    profileWriter,
		debuginfoManager: debuginfoProcessor,
		labelsManager:    labelsManager,
		normalizer:       address.NewNormalizer(logger, objFileCache),
		processMappings:  process.NewMapping(psMapCache),

		// Shared caches between all profilers.
		seenKernelStackIDFP:  make(map[int32]separateStack),
		seenUserStackIDFP:    make(map[int32]separateStack),
		seenUserStackIDDWARF: make(map[int32]separateStack),
		psMapCache:           psMapCache,
		objFileCache:         objFileCache,
		unwindTableBuilder:   unwind.NewUnwindTableBuilder(logger),

		profilingDuration: profilingDuration,

		mtx:       &sync.RWMutex{},
		byteOrder: byteorder.GetHostByteOrder(),
		metrics:   newMetrics(reg),

		memlockRlimit: memlockRlimit,

		debugProcessNames:    debugProcessNames,
		enableDWARFUnwinding: enableDWARFUnwinding,
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

func (p *CPU) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting cpu profiler")

	err := bpfCheck()
	if err != nil {
		return fmt.Errorf("bpf check: %w", err)
	}

	m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "parca",
	})
	if err != nil {
		return fmt.Errorf("new bpf module: %w", err)
	}
	defer m.Close()

	// Always need to be used after bpf.NewModuleFromBufferArgs to avoid limit override.
	rLimit, err := profiler.BumpMemlock(p.memlockRlimit, p.memlockRlimit)
	if err != nil {
		return fmt.Errorf("bump memlock rlimit: %w", err)
	}
	level.Debug(p.logger).Log("msg", "increased max memory locked rlimit", "limit", humanize.Bytes(rLimit.Cur))

	var matchers []*regexp.Regexp
	if len(p.debugProcessNames) > 0 {
		level.Info(p.logger).Log("msg", "process names specified, debugging processes", "metchers", strings.Join(p.debugProcessNames, ", "))
		for _, exp := range p.debugProcessNames {
			regex, err := regexp.Compile(exp)
			if err != nil {
				return fmt.Errorf("failed to compile regex: %w", err)
			}
			matchers = append(matchers, regex)
		}
	}

	debugEnabled := len(matchers) > 0
	if err := m.InitGlobalVariable(configKey, Config{Debug: debugEnabled}); err != nil {
		return fmt.Errorf("init global variable: %w", err)
	}

	if err := m.BPFLoadObject(); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	cpus := runtime.NumCPU()

	for i := 0; i < cpus; i++ {
		fd, err := unix.PerfEventOpen(&unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: 100,
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

	// Record start time for first profile
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
	zero := uint32(0)
	if err := programs.Update(unsafe.Pointer(&zero), unsafe.Pointer(&fd)); err != nil {
		return fmt.Errorf("failure updating: %w", err)
	}

	p.bpfMaps, err = initializeMaps(m, p.byteOrder)
	if err != nil {
		return fmt.Errorf("failed to initialize eBPF maps: %w", err)
	}

	if debugEnabled {
		pfs, err := procfs.NewDefaultFS()
		if err != nil {
			return fmt.Errorf("failed to create procfs: %w", err)
		}

		level.Debug(p.logger).Log("msg", "debug process matchers found, starting process watcher")
		// Update the debug pids map.
		go p.watchProcesses(ctx, pfs, matchers)
	}

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
			pprof, err := profiler.ConvertToPprof(p.LastProfileStartedAt(), prof)
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
				var objFiles []*objectfile.MappedObjectFile
				for _, mf := range maps {
					objFile, err := p.objFileCache.ObjectFileForProcess(mf.PID, mf.Mapping)
					if err != nil {
						processLastErrors[int(prof.ID.PID)] = err
						continue
					}
					objFiles = append(objFiles, objFile)
				}
				// Upload debug information of the discovered object files.
				p.debuginfoManager.EnsureUploaded(ctx, objFiles)
			}
		}

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

		procs, err := pfs.AllProcs()
		if err != nil {
			level.Error(p.logger).Log("msg", "failed to list processes", "err", err)
			continue
		}

		pids := []int{}
		for _, proc := range procs {
			comm, err := proc.Comm()
			if err != nil {
				level.Error(p.logger).Log("msg", "failed to get process name", "err", err)
				continue
			}

			if comm == "" {
				continue
			}

			for _, m := range matchers {
				if m.MatchString(comm) {
					level.Info(p.logger).Log("msg", "match found; debugging process", "pid", proc.PID, "comm", comm)
					pids = append(pids, proc.PID)
				}
			}
		}

		if len(pids) > 0 {
			level.Debug(p.logger).Log("msg", "updating debug pids map", "pids", fmt.Sprintf("%v", pids))
			// Only meant to be used for debugging, it is not safe to use in production.
			if err := p.bpfMaps.setDebugPIDs(pids); err != nil {
				level.Warn(p.logger).Log("msg", "failed to update debug pids map", "err", err)
			}
		} else {
			level.Debug(p.logger).Log("msg", "no processes matched the provided regex")
			if err := p.bpfMaps.setDebugPIDs(nil); err != nil {
				level.Warn(p.logger).Log("msg", "failed to update debug pids map", "err", err)
			}
			continue
		}

		// Can only be enabled when a debug process name is specified.
		if p.enableDWARFUnwinding {
			// Update unwind tables for the given pids.
			for _, pid := range pids {
				level.Info(p.logger).Log("msg", "adding unwind tables", "pid", pid)

				pt, err := p.unwindTableBuilder.UnwindTableForPid(pid)
				if err != nil {
					level.Warn(p.logger).Log("msg", "failed to build unwind table", "pid", pid, "err", err)
					continue
				}

				if err := p.bpfMaps.setUnwindTable(pid, pt); err != nil {
					level.Warn(p.logger).Log("msg", "failed to update unwind tables", "pid", pid, "err", err)
				}
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
		UserStackIDFP    int32
		KernelStackIDFP  int32
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
		// After we read stack ids from the BPF maps in each profile loop iteration,
		// we clean the whole map.
		// This might have unwanted consequences, such as stack id misses
		// even though we have seen that stack id in previous iterations.
		//
		// To ensure the soundness of stack resolution,
		// we should record the seen ids for the session and check ids against it
		// if it's not found in the BPF map.
		var (
			cachedStack separateStack
			cacheHit    bool
		)

		var userErr error
		if key.walkedWithDwarf() {
			if cachedStack, cacheHit = p.seenUserStackIDDWARF[key.UserStackIDDWARF]; cacheHit {
				copy(stack[:stackDepth], cachedStack[:])
			} else {
				// Stacks retrieved with our dwarf unwind information unwinder.
				userErr = p.bpfMaps.readUserStackWithDwarf(key.UserStackIDDWARF, &stack)
			}
			if userErr == nil {
				p.seenUserStackIDDWARF[key.UserStackIDDWARF] = cachedStack
			} else {
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
			}
		} else {
			if cachedStack, cacheHit = p.seenUserStackIDFP[key.UserStackIDFP]; cacheHit {
				copy(stack[:stackDepth], cachedStack[:])
			} else {
				// Stacks retrieved with the kernel's included frame pointer based unwinder.
				userErr = p.bpfMaps.readUserStack(key.UserStackID, &stack)
			}
			if userErr == nil {
				p.seenUserStackIDFP[key.UserStackIDFP] = cachedStack
			} else {
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
			}
			p.metrics.obtainMapAttempts.WithLabelValues(labelUser, labelKernelUnwind, labelSuccess).Inc()
		}

		var kernelErr error
		if cachedStack, cacheHit = p.seenKernelStackIDFP[key.KernelStackIDFP]; cacheHit {
			copy(stack[stackDepth:], cachedStack[:])
		} else {
			kernelErr = p.bpfMaps.readKernelStack(key.KernelStackID, &stack)
		}
		if kernelErr == nil {
			p.seenKernelStackIDFP[key.KernelStackIDFP] = cachedStack
		} else {
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
						ID: uint64(locationIndex + 1),
						// Try to normalize the address for a symbol for position-independent code.
						Address: p.normalizer.Normalize(int(key.PID), m, addr),
						Mapping: m,
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

		sample = &profile.Sample{
			Value:    []int64{int64(value)},
			Location: sampleLocations[id],
		}
		allSamples[id][stack] = sample
	}
	if it.Err() != nil {
		return nil, fmt.Errorf("failed iterator: %w", it.Err())
	}
	if err := p.bpfMaps.clean(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps", "err", err)
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
