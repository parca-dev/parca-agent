// Copyright 2021 The Parca Authors
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

package agent

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"C"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/maps"
	"github.com/parca-dev/parca-agent/pkg/perf"
)

//go:embed parca-agent.bpf.o
var bpfObj []byte

var seps = []byte{'\xff'}

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in parca-agent.bpf.c
	doubleStackDepth = 254
)

type Record struct {
	Labels  []*profilestorepb.Label
	Profile *profile.Profile
}

type CgroupProfilingTarget interface {
	PerfEventCgroupPath() string
	Labels() []*profilestorepb.Label
}

type NoopProfileStoreClient struct{}

func NewNoopProfileStoreClient() profilestorepb.ProfileStoreServiceClient {
	return &NoopProfileStoreClient{}
}

func (c *NoopProfileStoreClient) WriteRaw(ctx context.Context, in *profilestorepb.WriteRawRequest, opts ...grpc.CallOption) (*profilestorepb.WriteRawResponse, error) {
	return &profilestorepb.WriteRawResponse{}, nil
}

type CgroupProfiler struct {
	logger            log.Logger
	externalLabels    map[string]string
	ksymCache         *ksym.KsymCache
	target            CgroupProfilingTarget
	profilingDuration time.Duration
	sink              func(Record)
	cancel            func()

	pidMappingFileCache *maps.PidMappingFileCache
	batcher             *Batcher

	debugInfoExtractor *debuginfo.Extractor

	mtx                *sync.RWMutex
	lastProfileTakenAt time.Time
	lastError          error

	perfCache *perf.PerfCache
}

func NewCgroupProfiler(
	logger log.Logger,
	externalLabels map[string]string,
	ksymCache *ksym.KsymCache,
	batcher Batcher,
	debugInfoClient debuginfo.Client,
	target CgroupProfilingTarget,
	profilingDuration time.Duration,
	sink func(Record),
	tmp string,
) *CgroupProfiler {
	return &CgroupProfiler{
		logger:              logger,
		externalLabels:      externalLabels,
		ksymCache:           ksymCache,
		target:              target,
		profilingDuration:   profilingDuration,
		sink:                sink,
		pidMappingFileCache: maps.NewPidMappingFileCache(logger),
		perfCache:           perf.NewPerfCache(logger),
		writeClient:         writeClient,
		batcher:             &batcher,
		debugInfoExtractor: debuginfo.NewExtractor(
			log.With(logger, "component", "debuginfoextractor"),
			debugInfoClient,
			tmp,
		),
		mtx: &sync.RWMutex{},
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
	level.Debug(p.logger).Log("msg", "stopping cgroup profiler")
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *CgroupProfiler) Labels() []*profilestorepb.Label {
	labels := append(p.target.Labels(),
		&profilestorepb.Label{
			Name:  "__name__",
			Value: "parca_agent_cpu",
		})
	for key, value := range p.externalLabels {
		labels = append(labels, &profilestorepb.Label{
			Name:  key,
			Value: value,
		})
	}

	return labels
}

func (p *CgroupProfiler) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting cgroup profiler")
	ctx, p.cancel = context.WithCancel(ctx)

	m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "parca",
	})
	if err != nil {
		return fmt.Errorf("new bpf module: %w", err)
	}
	defer m.Close()

	err = m.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	cgroup, err := os.Open(p.target.PerfEventCgroupPath())
	if err != nil {
		return fmt.Errorf("open cgroup: %w", err)
	}
	defer cgroup.Close()

	cpus := runtime.NumCPU()
	for i := 0; i < cpus; i++ {
		// TODO(branz): Close the returned fd
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

		prog, err := m.GetProgram("do_sample")
		if err != nil {
			return fmt.Errorf("get bpf program: %w", err)
		}

		// Because this is fd based, even if our program crashes or is ended
		// without proper shutdown, things get cleaned up appropriately.

		// TODO(brancz): destroy the returned link via bpf_link__destroy
		_, err = prog.AttachPerfEvent(fd)
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

	ticker := time.NewTicker(p.profilingDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		t := time.Now()
		err := p.profileLoop(ctx, t, counts, stackTraces)

		p.loopReport(t, err)
	}
}

func (p *CgroupProfiler) profileLoop(ctx context.Context, now time.Time, counts, stackTraces *bpf.BPFMap) error {
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{{
			Type: "samples",
			Unit: "count",
		}},
		TimeNanos:     now.UnixNano(),
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

	// TODO(brancz): What was this for?
	//has_collision := false

	it := counts.Iterator()
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

		valueBytes, err := counts.GetValue(unsafe.Pointer(&keyBytes[0]))
		if err != nil {
			return fmt.Errorf("get count value: %w", err)
		}
		value := byteOrder.Uint64(valueBytes)

		stackBytes, err := stackTraces.GetValue(unsafe.Pointer(&userStackID))
		if err != nil {
			//profile.MissingStacks++
			continue
		}

		// Twice the stack depth because we have a user and a potential Kernel stack.
		stack := [doubleStackDepth]uint64{}
		err = binary.Read(bytes.NewBuffer(stackBytes), byteOrder, stack[:stackDepth])
		if err != nil {
			return fmt.Errorf("read user stack trace: %w", err)
		}

		if kernelStackID >= 0 {
			stackBytes, err = stackTraces.GetValue(unsafe.Pointer(&kernelStackID))
			if err != nil {
				//profile.MissingStacks++
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

		// Kernel stack
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

		// User stack
		perfMap, err := p.perfCache.CacheForPid(pid)
		if err != nil {
			// We expect only a minority of processes to have a JIT and produce
			// the perf map.
			level.Debug(p.logger).Log("msg", "no perfmap", "err", err)
		}
		for _, addr := range stack[:stackDepth] {
			if addr != uint64(0) {
				key := [2]uint64{uint64(pid), addr}
				locationIndex, ok := locationIndices[key]
				if !ok {
					locationIndex = len(locations)
					m, err := mapping.PidAddrMapping(pid, addr)
					if err != nil {
						level.Debug(p.logger).Log("msg", "failed to get mapping", "err", err)
					}
					l := &profile.Location{
						ID:      uint64(locationIndex + 1),
						Address: addr,
						Mapping: m,
					}

					// Does this addr point to JITed code?
					if perfMap != nil {
						// TODO(zecke): Log errors other than perf.NoSymbolFound
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

	var buildIDFiles map[string]maps.BuildIDFile
	prof.Mapping, buildIDFiles = mapping.AllMappings()
	prof.Location = locations

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

	for _, f := range userFunctions {
		f.ID = uint64(len(prof.Function)) + 1
		prof.Function = append(prof.Function, f)
	}

	p.debugInfoExtractor.EnsureUploaded(ctx, buildIDFiles)

	buf := bytes.NewBuffer(nil)
	err = prof.Write(buf)
	if err != nil {
		return err
	}
	labels := p.Labels()

	p.batcher.Scheduler(profilestorepb.RawProfileSeries{
		Labels:  &profilestorepb.LabelSet{Labels: labels},
		Samples: []*profilestorepb.RawSample{{RawProfile: buf.Bytes()}},
	})

	if err != nil {
		level.Error(p.logger).Log("msg", "failed to send profile", "err", err)
	}

	p.sink(Record{
		Labels:  labels,
		Profile: prof,
	})

	// BPF iterators need the previous value to iterate to the next, so we
	// can only delete the "previous" item once we've already iterated to
	// the next.

	it = stackTraces.Iterator()
	var prev []byte = nil
	for it.Next() {
		if prev != nil {
			err := stackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to delete stack trace", "err", err)
			}
		}

		key := it.Key()
		prev = make([]byte, len(key))
		copy(prev, key)
	}
	if prev != nil {
		err := stackTraces.DeleteKey(unsafe.Pointer(&prev[0]))
		if err != nil {
			level.Warn(p.logger).Log("msg", "failed to delete stack trace", "err", err)
		}
	}

	it = counts.Iterator()
	prev = nil
	for it.Next() {
		if prev != nil {
			err := counts.DeleteKey(unsafe.Pointer(&prev[0]))
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to delete count", "err", err)
			}
		}

		key := it.Key()
		prev = make([]byte, len(key))
		copy(prev, key)
	}
	if prev != nil {
		err := counts.DeleteKey(unsafe.Pointer(&prev[0]))
		if err != nil {
			level.Warn(p.logger).Log("msg", "failed to delete count", "err", err)
		}
	}

	return nil
}

func probabilisticSampling(ratio float64, labels []*profilestorepb.Label) bool {
	if ratio == 1.0 {
		return true
	}

	b := make([]byte, 0, 1024)
	for _, v := range labels {
		b = append(b, v.Name...)
		b = append(b, seps[0])
		b = append(b, v.Value...)
		b = append(b, seps[0])
	}
	h := fnv.New32a()
	h.Write(b)
	v := h.Sum32()
	return v <= uint32(float64(math.MaxUint32)*ratio)
}
