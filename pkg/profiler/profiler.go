// Copyright (c) 2022 The Parca Authors
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

package profiler

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"C" //gofumpt:skip

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/dustin/go-humanize"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"

	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/maps"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
)

//go:embed cpu-profiler.bpf.o
var bpfObj []byte

var errUnrecoverable = errors.New("unrecoverable error")

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in parca-agent.bpf.c
	doubleStackDepth = 254

	defaultRLimit = 1024 << 20 // ~1GB
)

type stack [doubleStackDepth]uint64

type bpfMaps struct {
	counts      *bpf.BPFMap
	stackTraces *bpf.BPFMap
}

// stackCountKey mirrors the struct in parca-agent.bpf.c
// NOTICE: The memory layout and alignment of the struct currently matches the struct in parca-agent.bpf.c.
// However, keep in mind that Go compiler injects padding to align the struct fields to be a multiple of 8 bytes.
// The Go spec says the address of a struct’s fields must be naturally aligned.
// https://dave.cheney.net/2015/10/09/padding-is-hard
// TODO: https://github.com/parca-dev/parca-agent/issues/207
type stackCountKey struct {
	PID           uint32
	UserStackID   int32
	KernelStackID int32
}

func (m bpfMaps) clean() error {
	// BPF iterators need the previous value to iterate to the next, so we
	// can only delete the "previous" item once we've already iterated to
	// the next.

	it := m.stackTraces.Iterator()
	var prev []byte = nil
	for it.Next() {
		if prev != nil {
			err := m.stackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete stack trace: %w", err)
			}
		}

		key := it.Key()
		prev = make([]byte, len(key))
		copy(prev, key)
	}
	if prev != nil {
		err := m.stackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
		if err != nil {
			return fmt.Errorf("failed to delete stack trace: %w", err)
		}
	}

	it = m.counts.Iterator()
	prev = nil
	for it.Next() {
		if prev != nil {
			err := m.counts.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				return fmt.Errorf("failed to delete count: %w", err)
			}
		}

		key := it.Key()
		prev = make([]byte, len(key))
		copy(prev, key)
	}
	if prev != nil {
		err := m.counts.DeleteKey(unsafe.Pointer(&prev[0]))
		if err != nil {
			return fmt.Errorf("failed to delete count: %w", err)
		}
	}

	return nil
}

type metrics struct {
	reg prometheus.Registerer

	missingStacks                *prometheus.CounterVec
	missingPIDs                  prometheus.Counter
	failedStackUnwindingAttempts *prometheus.CounterVec
	ksymCacheHitRate             *prometheus.CounterVec
}

func (m metrics) unregister() bool {
	return m.reg.Unregister(m.missingStacks) &&
		m.reg.Unregister(m.missingPIDs) &&
		m.reg.Unregister(m.failedStackUnwindingAttempts) &&
		m.reg.Unregister(m.ksymCacheHitRate)
}

func newMetrics(reg prometheus.Registerer, target model.LabelSet) *metrics {
	return &metrics{
		reg: reg,
		missingStacks: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_missing_stacks_total",
				Help:        "Number of missing profile stacks",
				ConstLabels: map[string]string{"target": target.String()},
			},
			[]string{"type"},
		),
		missingPIDs: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_missing_pid_total",
				Help:        "Number of missing PIDs",
				ConstLabels: map[string]string{"target": target.String()},
			},
		),
		failedStackUnwindingAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_failed_stack_unwinding_attempts_total",
				Help:        "Number of failed stack unwinding attempts",
				ConstLabels: map[string]string{"target": target.String()},
			},
			[]string{"type"},
		),
		ksymCacheHitRate: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_kernel_symbolizer_cache_total",
				Help:        "Hit rate for the kernel symbolizer cache",
				ConstLabels: map[string]string{"target": target.String()},
			},
			[]string{"type"},
		),
	}
}

type CgroupProfiler struct {
	logger log.Logger

	mtx    *sync.RWMutex
	cancel func()

	pidMappingFileCache *maps.PIDMappingFileCache
	perfCache           *perf.Cache
	ksymCache           *ksym.Cache
	objCache            objectfile.Cache

	bpfMaps   *bpfMaps
	byteOrder binary.ByteOrder

	lastError          error
	lastProfileTakenAt time.Time

	writeClient profilestorepb.ProfileStoreServiceClient
	debugInfo   *debuginfo.DebugInfo

	target            model.LabelSet
	profilingDuration time.Duration

	profileBufferPool sync.Pool

	metrics *metrics
}

func NewCgroupProfiler(
	logger log.Logger,
	reg prometheus.Registerer,
	ksymCache *ksym.Cache,
	objCache objectfile.Cache,
	writeClient profilestorepb.ProfileStoreServiceClient,
	debugInfoClient debuginfo.Client,
	target model.LabelSet,
	profilingDuration time.Duration,
	tmp string,
) *CgroupProfiler {
	return &CgroupProfiler{
		logger:              log.With(logger, "labels", target.String()),
		mtx:                 &sync.RWMutex{},
		target:              target,
		profilingDuration:   profilingDuration,
		writeClient:         writeClient,
		ksymCache:           ksymCache,
		pidMappingFileCache: maps.NewPIDMappingFileCache(logger),
		perfCache:           perf.NewPerfCache(logger),
		objCache:            objCache,
		debugInfo: debuginfo.New(
			log.With(logger, "component", "debuginfo"),
			debugInfoClient,
			tmp,
		),
		profileBufferPool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(nil)
			},
		},
		byteOrder: byteorder.GetHostByteOrder(),
		metrics:   newMetrics(reg, target),
	}
}

func (p *CgroupProfiler) LastProfileTakenAt() time.Time {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastProfileTakenAt
}

func (p *CgroupProfiler) LastError() error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastError
}

func (p *CgroupProfiler) Stop() {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	level.Debug(p.logger).Log("msg", "stopping cgroup profiler")
	if !p.metrics.unregister() {
		level.Debug(p.logger).Log("msg", "cannot unregister metrics")
	}
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *CgroupProfiler) Labels() model.LabelSet {
	labels := model.LabelSet{
		"__name__": "parca_agent_cpu",
	}

	for labelname, labelvalue := range p.target {
		if !strings.HasPrefix(string(labelname), "__") {
			labels[labelname] = labelvalue
		}
	}

	return labels
}

func (p *CgroupProfiler) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting cgroup profiler")

	p.mtx.Lock()
	ctx, p.cancel = context.WithCancel(ctx)
	p.mtx.Unlock()

	m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "parca",
	})
	if err != nil {
		return fmt.Errorf("new bpf module: %w", err)
	}
	defer m.Close()

	// Always need to be used after bpf.NewModuleFromBufferArgs to avoid limit override.
	if err := p.bumpMemlockRlimit(); err != nil {
		return fmt.Errorf("bump memlock rlimit: %w", err)
	}

	if err := m.BPFLoadObject(); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	cgroup, err := os.Open(string(p.target[agent.CgroupPathLabelName]))
	if err != nil {
		return fmt.Errorf("open cgroup: %w", err)
	}
	defer cgroup.Close()

	cpus := runtime.NumCPU()
	for i := 0; i < cpus; i++ {
		fd, err := unix.PerfEventOpen(&unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: 100,
			Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		}, int(cgroup.Fd()), i, -1, unix.PERF_FLAG_PID_CGROUP)
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

		prog, err := m.GetProgram("do_sample")
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

	counts, err := m.GetMap("counts")
	if err != nil {
		return fmt.Errorf("get counts map: %w", err)
	}

	stackTraces, err := m.GetMap("stack_traces")
	if err != nil {
		return fmt.Errorf("get stack traces map: %w", err)
	}
	p.bpfMaps = &bpfMaps{counts: counts, stackTraces: stackTraces}

	ticker := time.NewTicker(p.profilingDuration)
	defer ticker.Stop()

	level.Debug(p.logger).Log("msg", "start profiling loop")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		captureTime := time.Now()
		err := p.profileLoop(ctx, captureTime)
		if err != nil {
			level.Warn(p.logger).Log("msg", "profile loop error", "err", err)
		}

		p.loopReport(captureTime, err)
	}
}

func (p *CgroupProfiler) profileLoop(ctx context.Context, captureTime time.Time) (err error) {
	var (
		mappings      = maps.NewMapping(p.pidMappingFileCache)
		kernelMapping = &profile.Mapping{
			File: "[kernel.kallsyms]",
		}

		samples         = map[stack]*profile.Sample{}
		locations       = []*profile.Location{}
		kernelLocations = []*profile.Location{}
		userLocations   = map[uint32][]*profile.Location{} // PID -> []*profile.Location
		locationIndices = map[[2]uint64]int{}              // [PID, Address] -> index in locations
	)

	// TODO(kakkoyun): Use libbpf batch functions.
	it := p.bpfMaps.counts.Iterator()
	for it.Next() {
		// This byte slice is only valid for this iteration, so it must be
		// copied if we want to do anything with it outside this loop.
		keyBytes := it.Key()

		var key stackCountKey
		// NOTICE: This works because the key struct in Go and the key struct in C has exactly the same memory layout.
		// See the comment in stackCountKey for more details.
		if err := binary.Read(bytes.NewBuffer(keyBytes), p.byteOrder, &key); err != nil {
			return fmt.Errorf("read stack count key: %w", err)
		}

		// Twice the stack depth because we have a user and a potential Kernel stack.
		// Read order matters, since we read from the key buffer.
		stack := stack{}
		userErr := p.readUserStack(key.UserStackID, &stack)
		if userErr != nil {
			if errors.Is(userErr, errUnrecoverable) {
				return userErr
			}
			level.Debug(p.logger).Log("msg", "failed to read user stack", "err", userErr)
		}
		kernelErr := p.readKernelStack(key.KernelStackID, &stack)
		if kernelErr != nil {
			if errors.Is(kernelErr, errUnrecoverable) {
				return kernelErr
			}
			level.Debug(p.logger).Log("msg", "failed to read kernel stack", "err", kernelErr)
		}
		if userErr != nil && kernelErr != nil {
			// Both stacks are missing. Nothing to do.
			continue
		}

		value, err := p.readValue(keyBytes)
		if err != nil {
			return fmt.Errorf("read value: %w", err)
		}
		if value == 0 {
			// This should never happen, but it's here just in case.
			// If we have a zero value, we don't want to add it to the profile.
			continue
		}

		sample, ok := samples[stack]
		if ok {
			// We already have a sample with this stack trace, so just add
			// it to the previous one.
			sample.Value[0] += int64(value)
			continue
		}
		sampleLocations := []*profile.Location{}

		// Collect Kernel stack trace samples.
		for _, addr := range stack[stackDepth:] {
			if addr != uint64(0) {
				key := [2]uint64{0, addr}
				// PID 0 not possible so we'll use it to identify the kernel.
				locationIndex, ok := locationIndices[key]
				if !ok {
					locationIndex = len(locations)
					l := &profile.Location{
						ID:      uint64(locationIndex + 1),
						Address: addr,
						Mapping: kernelMapping,
					}
					locations = append(locations, l)
					kernelLocations = append(kernelLocations, l)
					locationIndices[key] = locationIndex
				}
				sampleLocations = append(sampleLocations, locations[locationIndex])
			}
		}

		// Collect User stack trace samples.
		for _, addr := range stack[:stackDepth] {
			if addr != uint64(0) {
				k := [2]uint64{uint64(key.PID), addr}
				locationIndex, ok := locationIndices[k]
				if !ok {
					locationIndex = len(locations)

					m, err := mappings.PIDAddrMapping(key.PID, addr)
					if err != nil {
						if !errors.Is(err, maps.ErrNotFound) {
							level.Warn(p.logger).Log("msg", "failed to get process mapping", "err", err)
						}
					}

					l := &profile.Location{
						ID: uint64(locationIndex + 1),
						// Try to normalize the address for a symbol for position independent code.
						Address: p.normalizeAddress(m, key.PID, addr),
						Mapping: m,
					}

					locations = append(locations, l)
					userLocations[key.PID] = append(userLocations[key.PID], l)
					locationIndices[k] = locationIndex
				}
				sampleLocations = append(sampleLocations, locations[locationIndex])
			}
		}

		sample = &profile.Sample{
			Value:    []int64{int64(value)},
			Location: sampleLocations,
		}
		samples[stack] = sample
	}
	if it.Err() != nil {
		return fmt.Errorf("failed iterator: %w", it.Err())
	}

	prof, err := p.buildProfile(ctx, captureTime, samples, locations, kernelLocations, userLocations, mappings, kernelMapping)
	if err != nil {
		return fmt.Errorf("failed to build profile: %w", err)
	}

	if err := p.writeProfile(ctx, prof); err != nil {
		level.Error(p.logger).Log("msg", "failed to send profile", "err", err)
	}

	if err := p.bpfMaps.clean(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps", "err", err)
	}

	ksymCacheStats := p.ksymCache.Stats
	level.Debug(p.logger).Log("msg", "Kernel symbol cache stats", "stats", ksymCacheStats.String())
	p.metrics.ksymCacheHitRate.WithLabelValues("hits").Add(float64(ksymCacheStats.Hits))
	p.metrics.ksymCacheHitRate.WithLabelValues("total").Add(float64(ksymCacheStats.Total))

	return nil
}

func (p *CgroupProfiler) loopReport(lastProfileTakenAt time.Time, lastError error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.lastProfileTakenAt = lastProfileTakenAt
	p.lastError = lastError
}

func (p *CgroupProfiler) buildProfile(
	ctx context.Context,
	captureTime time.Time,
	samples map[stack]*profile.Sample,
	locations []*profile.Location,
	kernelLocations []*profile.Location,
	userLocations map[uint32][]*profile.Location,
	mappings *maps.Mapping,
	kernelMapping *profile.Mapping,
) (*profile.Profile, error) {
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{{
			Type: "samples",
			Unit: "count",
		}},
		TimeNanos:     captureTime.UnixNano(),
		DurationNanos: int64(p.profilingDuration),

		// We sample at 100Hz, which is every 10 Million nanoseconds.
		PeriodType: &profile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		Period: 10000000,
	}

	// Build Profile from samples, locations and mappings.
	for _, s := range samples {
		prof.Sample = append(prof.Sample, s)
	}

	// Locations.
	prof.Location = locations

	// User mappings.
	var mappedFiles []maps.ProcessMapping
	prof.Mapping, mappedFiles = mappings.AllMappings()

	// Upload debug information of the discovered object files.
	go func() {
		var objFiles []*objectfile.MappedObjectFile
		for _, mf := range mappedFiles {
			objFile, err := p.objCache.ObjectFileForProcess(mf.PID, mf.Mapping)
			if err != nil {
				continue
			}
			objFiles = append(objFiles, objFile)
		}
		p.debugInfo.EnsureUploaded(ctx, objFiles)
	}()

	// Kernel mappings.
	kernelMapping.ID = uint64(len(prof.Mapping)) + 1
	prof.Mapping = append(prof.Mapping, kernelMapping)

	kernelFunctions, err := p.resolveKernelFunctions(kernelLocations)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve kernel functions: %w", err)
	}
	for _, f := range kernelFunctions {
		f.ID = uint64(len(prof.Function)) + 1
		prof.Function = append(prof.Function, f)
	}

	userFunctions := p.resolveJITedFunctions(userLocations)
	for _, f := range userFunctions {
		f.ID = uint64(len(prof.Function)) + 1
		prof.Function = append(prof.Function, f)
	}

	return prof, nil
}

// resolveKernelFunctions resolves the just-in-time compiled functions using the perf map.
func (p *CgroupProfiler) resolveJITedFunctions(locations map[uint32][]*profile.Location) map[uint64]*profile.Function {
	userFunctions := map[uint64]*profile.Function{}
	for pid, locations := range locations {
		perfMap, err := p.perfCache.CacheForPID(pid)
		if err != nil {
			// We expect only a minority of processes to have a JIT and produce the perf map.
			if !errors.Is(err, perf.ErrNotFound) {
				level.Warn(p.logger).Log("msg", "failed to obtain perf map for pid", "pid", pid, "err", err)
			}
		}
		if perfMap != nil {
			for _, loc := range locations {
				jitFunction, ok := userFunctions[loc.Address]
				if !ok {
					sym, err := perfMap.Lookup(loc.Address)
					if err != nil {
						if !errors.Is(err, perf.ErrNotFound) {
							continue
						}
						level.Debug(p.logger).Log("msg", "failed to lookup JIT symbol", "address", loc.Address, "err", err)
						continue
					}
					jitFunction = &profile.Function{Name: sym}
					userFunctions[loc.Address] = jitFunction
				}
				if jitFunction != nil {
					loc.Line = []profile.Line{{Function: jitFunction}}
				}
			}
		}
	}
	return userFunctions
}

// resolveKernelFunctions resolves kernel function names.
func (p *CgroupProfiler) resolveKernelFunctions(kernelLocations []*profile.Location) (map[uint64]*profile.Function, error) {
	kernelAddresses := map[uint64]struct{}{}
	for _, kloc := range kernelLocations {
		kernelAddresses[kloc.Address] = struct{}{}
	}
	kernelSymbols, err := p.ksymCache.Resolve(kernelAddresses)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel symbols: %w", err)
	}
	kernelFunctions := map[uint64]*profile.Function{}
	for _, kloc := range kernelLocations {
		kernelFunction, ok := kernelFunctions[kloc.Address]
		if !ok {
			name := kernelSymbols[kloc.Address]
			if name == "" {
				name = "not found"
			}
			kernelFunction = &profile.Function{
				Name: name,
			}
			kernelFunctions[kloc.Address] = kernelFunction
		}
		if kernelFunction != nil {
			kloc.Line = []profile.Line{{Function: kernelFunction}}
		}
	}
	return kernelFunctions, nil
}

// readUserStack reads the user stack trace from the stacktraces ebpf map into the given buffer.
func (p *CgroupProfiler) readUserStack(userStackID int32, stack *stack) error {
	if userStackID == 0 {
		p.metrics.failedStackUnwindingAttempts.WithLabelValues("user").Inc()
		return errors.New("user stack ID is 0, probably stack unwinding failed")
	}

	stackBytes, err := p.bpfMaps.stackTraces.GetValue(unsafe.Pointer(&userStackID))
	if err != nil {
		p.metrics.missingStacks.WithLabelValues("user").Inc()
		return fmt.Errorf("read user stack trace: %w", err)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), p.byteOrder, stack[:stackDepth]); err != nil {
		return fmt.Errorf("read user stack bytes, %s: %w", err, errUnrecoverable)
	}

	return nil
}

// readKernelStack reads the kernel stack trace from the stacktraces ebpf map into the given buffer.
func (p *CgroupProfiler) readKernelStack(kernelStackID int32, stack *stack) error {
	if kernelStackID == 0 {
		p.metrics.failedStackUnwindingAttempts.WithLabelValues("kernel").Inc()
		return errors.New("kernel stack ID is 0, probably stack unwinding failed")
	}

	stackBytes, err := p.bpfMaps.stackTraces.GetValue(unsafe.Pointer(&kernelStackID))
	if err != nil {
		p.metrics.missingStacks.WithLabelValues("kernel").Inc()
		return fmt.Errorf("read kernel stack trace: %w", err)
	}

	if err := binary.Read(bytes.NewBuffer(stackBytes), p.byteOrder, stack[stackDepth:]); err != nil {
		return fmt.Errorf("read kernel stack bytes, %s: %w", err, errUnrecoverable)
	}

	return nil
}

// readValue reads the value of the given key from the counts ebpf map.
func (p *CgroupProfiler) readValue(keyBytes []byte) (uint64, error) {
	valueBytes, err := p.bpfMaps.counts.GetValue(unsafe.Pointer(&keyBytes[0]))
	if err != nil {
		return 0, fmt.Errorf("get count value: %w", err)
	}
	return p.byteOrder.Uint64(valueBytes), nil
}

// normalizeProfile calculates the base addresses of a position-independent binary and normalizes captured locations accordingly.
func (p *CgroupProfiler) normalizeAddress(m *profile.Mapping, pid uint32, addr uint64) uint64 {
	if m == nil {
		return addr
	}

	logger := log.With(p.logger, "pid", pid, "buildID", m.BuildID)
	if m.Unsymbolizable() {
		level.Debug(logger).Log("msg", "mapping is unsymbolizable")
		return addr
	}

	objFile, err := p.objCache.ObjectFileForProcess(pid, m)
	if err != nil {
		level.Debug(logger).Log("msg", "failed to open object file", "err", err)
		return addr
	}

	// Transform the address by normalizing Kernel memory offsets.
	normalizedAddr, err := objFile.ObjAddr(addr)
	if err != nil {
		level.Debug(logger).Log("msg", "failed to get normalized address from object file", "err", err)
		return addr
	}

	return normalizedAddr
}

// writeProfile sends the profile using the designated write client..
func (p *CgroupProfiler) writeProfile(ctx context.Context, prof *profile.Profile) error {
	//nolint:forcetypeassert
	buf := p.profileBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		p.profileBufferPool.Put(buf)
	}()
	if err := prof.Write(buf); err != nil {
		return err
	}

	var (
		labelOldFormat = make([]*profilestorepb.Label, 0, len(p.Labels()))
		i              = 0
	)
	for key, value := range p.Labels() {
		labelOldFormat = append(labelOldFormat, &profilestorepb.Label{
			Name:  string(key),
			Value: string(value),
		})
		i++
	}

	// NOTICE: This is a batch client, so nothing will be sent immediately.
	// Make sure that the batch write client has the correct behaviour if you change any parameters.
	_, err := p.writeClient.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
		Normalized: true,
		Series: []*profilestorepb.RawProfileSeries{{
			Labels: &profilestorepb.LabelSet{Labels: labelOldFormat},
			Samples: []*profilestorepb.RawSample{{
				RawProfile: buf.Bytes(),
			}},
		}},
	})

	return err
}

// bumpMemlockRlimit increases the current memlock limit to a value more reasonable for the profiler's needs.
func (p *CgroupProfiler) bumpMemlockRlimit() error {
	// TODO(kakkoyun): https://github.com/cilium/ebpf/blob/v0.8.1/rlimit/rlimit.go
	rLimit := syscall.Rlimit{
		Cur: uint64(defaultRLimit),
		Max: uint64(defaultRLimit),
	}

	// RLIMIT_MEMLOCK is 0x8.
	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		return fmt.Errorf("failed to increase rlimit: %w", err)
	}

	rLimit = syscall.Rlimit{}
	if err := syscall.Getrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		return fmt.Errorf("failed to get rlimit: %w", err)
	}
	level.Debug(p.logger).Log("msg", "increased max memory locked rlimit", "limit", humanize.Bytes(rLimit.Cur))

	return nil
}
