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
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"C" //nolint:typecheck

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

//go:embed parca-agent.bpf.o
var bpfObj []byte

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in parca-agent.bpf.c
	doubleStackDepth = 254

	defaultRlimit = 1024 << 20 // ~1GB
)

type bpfMaps struct {
	counts      *bpf.BPFMap
	stackTraces *bpf.BPFMap
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

type CgroupProfiler struct {
	logger log.Logger
	reg    prometheus.Registerer

	mtx    *sync.RWMutex
	cancel func()

	pidMappingFileCache *maps.PIDMappingFileCache
	perfCache           *perf.Cache
	ksymCache           *ksym.Cache
	objCache            objectfile.Cache

	bpfMaps *bpfMaps

	missingStacks      *prometheus.CounterVec
	lastError          error
	lastProfileTakenAt time.Time

	writeClient profilestorepb.ProfileStoreServiceClient
	debugInfo   *debuginfo.DebugInfo

	target            model.LabelSet
	profilingDuration time.Duration

	profileBufferPool sync.Pool
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
		reg:                 reg,
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
		missingStacks: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_missing_stacks_total",
				Help:        "Number of missing profile stacks",
				ConstLabels: map[string]string{"target": target.String()},
			},
			[]string{"type"},
		),
		profileBufferPool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(nil)
			},
		},
	}
}

func (p *CgroupProfiler) loopReport(lastProfileTakenAt time.Time, lastError error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.lastProfileTakenAt = lastProfileTakenAt
	p.lastError = lastError
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
	if !p.reg.Unregister(p.missingStacks) {
		level.Debug(p.logger).Log("msg", "cannot unregister metric")
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
		defer func() {
			if err := syscall.Close(fd); err != nil {
				level.Error(p.logger).Log("msg", "close perf event", "err", err)
			}
		}()

		prog, err := m.GetProgram("do_sample")
		if err != nil {
			return fmt.Errorf("get bpf program: %w", err)
		}

		// Because this is fd based, even if our program crashes or is ended
		// without proper shutdown, things get cleaned up appropriately.
		link, err := prog.AttachPerfEvent(fd)
		if err != nil {
			return fmt.Errorf("attach perf event: %w", err)
		}
		defer func() {
			if err := link.Destroy(); err != nil {
				level.Error(p.logger).Log("msg", "destroy perf event link", "err", err)
			}
		}()
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

func (p *CgroupProfiler) profileLoop(ctx context.Context, captureTime time.Time) error {
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

	mapping := maps.NewMapping(p.pidMappingFileCache)
	kernelMapping := &profile.Mapping{
		// TODO(kakkoyun): Check if this conflicts with https://github.com/google/pprof/pull/675/files
		File: "[kernel.kallsyms]",
	}
	kernelFunctions := map[uint64]*profile.Function{}
	userFunctions := map[[2]uint64]*profile.Function{}

	// 2 uint64 1 for PID and 1 for Addr
	locations := []*profile.Location{}
	kernelLocations := []*profile.Location{}
	kernelAddresses := map[uint64]struct{}{}
	locationIndices := map[[2]uint64]int{}
	samples := map[[doubleStackDepth]uint64]*profile.Sample{}

	it := p.bpfMaps.counts.Iterator()
	byteOrder := byteorder.GetHostByteOrder()

	// TODO(brancz): Use libbpf batch functions.
	for it.Next() {
		// This byte slice is only valid for this iteration, so it must be
		// copied if we want to do anything with it outside of this loop.
		keyBytes := it.Key()

		r := bytes.NewBuffer(keyBytes)

		pidBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, pidBytes); err != nil {
			return fmt.Errorf("read pid bytes: %w", err)
		}
		pid := byteOrder.Uint32(pidBytes)

		userStackIDBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, userStackIDBytes); err != nil {
			return fmt.Errorf("read user stack ID bytes: %w", err)
		}
		userStackID := int32(byteOrder.Uint32(userStackIDBytes))

		kernelStackIDBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, kernelStackIDBytes); err != nil {
			return fmt.Errorf("read kernel stack ID bytes: %w", err)
		}
		kernelStackID := int32(byteOrder.Uint32(kernelStackIDBytes))

		valueBytes, err := p.bpfMaps.counts.GetValue(unsafe.Pointer(&keyBytes[0]))
		if err != nil {
			return fmt.Errorf("get count value: %w", err)
		}
		value := byteOrder.Uint64(valueBytes)

		stackBytes, err := p.bpfMaps.stackTraces.GetValue(unsafe.Pointer(&userStackID))
		if err != nil {
			p.missingStacks.WithLabelValues("user").Inc()
			continue
		}

		// Twice the stack depth because we have a user and a potential Kernel stack.
		stack := [doubleStackDepth]uint64{}
		err = binary.Read(bytes.NewBuffer(stackBytes), byteOrder, stack[:stackDepth])
		if err != nil {
			return fmt.Errorf("read user stack trace: %w", err)
		}

		if kernelStackID >= 0 {
			stackBytes, err = p.bpfMaps.stackTraces.GetValue(unsafe.Pointer(&kernelStackID))
			if err != nil {
				p.missingStacks.WithLabelValues("kernel").Inc()
				continue
			}

			err = binary.Read(bytes.NewBuffer(stackBytes), byteOrder, stack[stackDepth:])
			if err != nil {
				return fmt.Errorf("read kernel stack trace: %w", err)
			}
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
					kernelAddresses[addr] = struct{}{}
					locationIndices[key] = locationIndex
				}
				sampleLocations = append(sampleLocations, locations[locationIndex])
			}
		}

		perfMap, err := p.perfCache.CacheForPID(pid)
		if err != nil {
			// We expect only a minority of processes to have a JIT and produce
			// the perf map.
			if !errors.Is(err, perf.ErrNotFound) {
				level.Warn(p.logger).Log("msg", "failed to obtain perf map for pid", "pid", pid, "err", err)
			}
		}
		// Collect User stack trace samples.
		for _, addr := range stack[:stackDepth] {
			if addr != uint64(0) {
				key := [2]uint64{uint64(pid), addr}
				locationIndex, ok := locationIndices[key]
				if !ok {
					locationIndex = len(locations)

					m, err := mapping.PIDAddrMapping(pid, addr)
					if err != nil {
						if !errors.Is(err, maps.ErrNotFound) {
							level.Warn(p.logger).Log("msg", "failed to get process mapping", "err", err)
						}
					}

					l := &profile.Location{
						ID: uint64(locationIndex + 1),
						// Try to normalize the address for a symbol for position independent code.
						Address: p.normalizeAddress(m, pid, addr),
						Mapping: m,
					}

					// Resolve JIT symbols using perf maps.s
					if perfMap != nil {
						// TODO(zecke): Log errors other than perf.ErrNoSymbolFound
						jitFunction, ok := userFunctions[key]
						if !ok {
							if sym, err := perfMap.Lookup(addr); err == nil {
								jitFunction = &profile.Function{Name: sym}
								userFunctions[key] = jitFunction
							}
						}
						if jitFunction != nil {
							l.Line = []profile.Line{{Function: jitFunction}}
						}
					}

					locations = append(locations, l)
					locationIndices[key] = locationIndex
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

	// Build Profile from samples, locations and mappings.
	for _, s := range samples {
		prof.Sample = append(prof.Sample, s)
	}

	var mappedFiles []maps.ProcessMapping
	prof.Mapping, mappedFiles = mapping.AllMappings()
	prof.Location = locations

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

	// Resolve Kernel function names.
	kernelSymbols, err := p.ksymCache.Resolve(kernelAddresses)
	if err != nil {
		return fmt.Errorf("resolve kernel symbols: %w", err)
	}
	for _, l := range kernelLocations {
		kernelFunction, ok := kernelFunctions[l.Address]
		if !ok {
			name := kernelSymbols[l.Address]
			if name == "" {
				name = "not found"
			}
			kernelFunction = &profile.Function{
				Name: name,
			}
			kernelFunctions[l.Address] = kernelFunction
		}
		if kernelFunction != nil {
			l.Line = []profile.Line{{Function: kernelFunction}}
		}
	}
	for _, f := range kernelFunctions {
		f.ID = uint64(len(prof.Function)) + 1
		prof.Function = append(prof.Function, f)
	}
	kernelMapping.ID = uint64(len(prof.Mapping)) + 1
	prof.Mapping = append(prof.Mapping, kernelMapping)

	// Resolve user function names.
	for _, f := range userFunctions {
		f.ID = uint64(len(prof.Function)) + 1
		prof.Function = append(prof.Function, f)
	}

	if err := p.sendProfile(ctx, prof); err != nil {
		level.Error(p.logger).Log("msg", "failed to send profile", "err", err)
	}

	if err := p.bpfMaps.clean(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps", "err", err)
	}

	return nil
}

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

func (p *CgroupProfiler) sendProfile(ctx context.Context, prof *profile.Profile) error {
	buf := p.profileBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		p.profileBufferPool.Put(buf)
	}()
	if err := prof.Write(buf); err != nil {
		return err
	}

	var labeloldformat []*profilestorepb.Label

	for key, value := range p.Labels() {
		labeloldformat = append(labeloldformat,
			&profilestorepb.Label{
				Name:  string(key),
				Value: string(value),
			})
	}

	// NOTICE: This is a batch client, so nothing will be sent immediately.
	// Make sure that the batch write client has the correct behaviour if you change any parameters.
	_, err := p.writeClient.WriteRaw(ctx, &profilestorepb.WriteRawRequest{
		Normalized: true,
		Series: []*profilestorepb.RawProfileSeries{{
			Labels: &profilestorepb.LabelSet{Labels: labeloldformat},
			Samples: []*profilestorepb.RawSample{{
				RawProfile: buf.Bytes(),
			}},
		}},
	})

	return err
}

// bumpMemlockRlimit increases the current memlock limit to a value more reasonable for the profiler's needs.
func (p *CgroupProfiler) bumpMemlockRlimit() error {
	rLimit := syscall.Rlimit{
		Cur: uint64(defaultRlimit),
		Max: uint64(defaultRlimit),
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
