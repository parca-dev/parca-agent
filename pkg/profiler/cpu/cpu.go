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
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/dustin/go-humanize"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/pkg/address"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

//go:embed cpu-profiler.bpf.o
var bpfObj []byte

const (
	stackDepth       = 127 // Always needs to be sync with MAX_STACK_DEPTH in BPF program.
	doubleStackDepth = stackDepth * 2

	defaultRLimit = 1024 << 20 // ~1GB

	programName = "profile_cpu"

	kernelMappingFileName = "[kernel.kallsyms]"
)

type combinedStack [doubleStackDepth]uint64

type CPU struct {
	logger            log.Logger
	profilingDuration time.Duration

	symbolizer      profiler.Symbolizer
	normalizer      profiler.Normalizer
	processMappings *process.Mapping

	profileWriter     profiler.ProfileWriter
	debugInfoManager  profiler.DebugInfoManager
	metadataProviders []profiler.MetadataProvider

	psMapCache   profiler.ProcessMapCache
	objFileCache profiler.ObjectFileCache

	metrics *metrics

	mtx *sync.RWMutex

	bpfMaps   *bpfMaps
	byteOrder binary.ByteOrder

	// Reporting.
	lastError                      error
	lastProcessErrors              map[int]error
	lastSuccessfulProfileStartedAt time.Time
	lastProfileStartedAt           time.Time
}

func NewCPUProfiler(
	logger log.Logger,
	reg prometheus.Registerer,
	symbolizer profiler.Symbolizer,
	psMapCache profiler.ProcessMapCache,
	objFileCache profiler.ObjectFileCache,
	profileWriter profiler.ProfileWriter,
	debugInfoProcessor profiler.DebugInfoManager,
	metadataProviders []profiler.MetadataProvider,
	profilingDuration time.Duration,
) *CPU {
	return &CPU{
		logger: logger,

		symbolizer:        symbolizer,
		profileWriter:     profileWriter,
		debugInfoManager:  debugInfoProcessor,
		metadataProviders: metadataProviders,
		normalizer:        address.NewNormalizer(logger, objFileCache),
		processMappings:   process.NewMapping(psMapCache),

		// Shared caches between all profilers.
		psMapCache:   psMapCache,
		objFileCache: objFileCache,

		profilingDuration: profilingDuration,

		mtx:       &sync.RWMutex{},
		byteOrder: byteorder.GetHostByteOrder(),
		metrics:   newMetrics(reg),
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

func (p *CPU) LastProcessErrors() map[int]error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastProcessErrors
}

func (p *CPU) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting cpu profiler")

	m, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObj,
		BPFObjName: "parca",
	})
	if err != nil {
		return fmt.Errorf("new bpf module: %w", err)
	}
	defer m.Close()

	// Always need to be used after bpf.NewModuleFromBufferArgs to avoid limit override.
	rLimit, err := profiler.BumpMemlock(defaultRLimit, defaultRLimit)
	if err != nil {
		return fmt.Errorf("bump memlock rlimit: %w", err)
	}
	level.Debug(p.logger).Log("msg", "increased max memory locked rlimit", "limit", humanize.Bytes(rLimit.Cur))

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

	counts, err := m.GetMap(countsMapName)
	if err != nil {
		return fmt.Errorf("get counts map: %w", err)
	}

	stackTraces, err := m.GetMap(stackTracesMapName)
	if err != nil {
		return fmt.Errorf("get stack traces map: %w", err)
	}
	p.bpfMaps = &bpfMaps{
		byteOrder:   p.byteOrder,
		counts:      counts,
		stackTraces: stackTraces,
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

		profiles, err := p.obtainProfiles(ctx)
		if err != nil {
			level.Warn(p.logger).Log("msg", "failed to obtain profiles from eBPF maps", "err", err)
		}

		errs := map[int]error{}

		for _, prof := range profiles {
			err = p.symbolizer.Symbolize(prof)
			if err != nil {
				level.Debug(p.logger).Log("msg", "failed to symbolize profile", "pid", prof.PID, "err", err)
				errs[int(prof.PID)] = err
			}

			// ConvertToPprof can combine multiple profiles into a single profile,
			// however right now we chose to send each profile separately.
			// This is not too inefficient as we batch the profiles in a single RPC message,
			// using the batch profiler writer.
			pprof, err := profiler.ConvertToPprof(p.LastProfileStartedAt(), prof)
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to convert profile to pprof", "pid", prof.PID, "err", err)
				errs[int(prof.PID)] = err
				continue
			}
			if err := p.profileWriter.Write(ctx, p.labels(prof.PID), pprof); err != nil {
				level.Warn(p.logger).Log("msg", "failed to write profile", "pid", prof.PID, "err", err)
				errs[int(prof.PID)] = err
				continue
			}
			if p.debugInfoManager != nil {
				maps := p.processMappings.MapsForPID(int(prof.PID))
				var objFiles []*objectfile.MappedObjectFile
				for _, mf := range maps {
					objFile, err := p.objFileCache.ObjectFileForProcess(mf.PID, mf.Mapping)
					if err != nil {
						errs[int(prof.PID)] = err
						continue
					}
					objFiles = append(objFiles, objFile)
				}
				// Upload debug information of the discovered object files.
				go p.debugInfoManager.EnsureUploaded(ctx, objFiles)
			}
		}

		p.report(err, errs)
	}
}

// labels fetches process specific labels to the profiles.
func (p *CPU) labels(pid profiler.PID) model.LabelSet {
	labels := model.LabelSet{
		"__name__": model.LabelValue(p.Name()),
		"pid":      model.LabelValue(strconv.FormatUint(uint64(pid), 10)),
	}

	for _, provider := range p.metadataProviders {
		// Add service discovery metadata, such as the Kubernetes pod where the
		// process is running, among others.
		lbl, err := provider.Labels(int(pid))
		if err != nil {
			// NOTICE: Can be too noisy. Keeping this for debugging purposes.
			// level.Debug(p.logger).Log("msg", "failed to get metadata", "provider", provider.Name(), "err", err)
			continue
		}
		for k, v := range lbl {
			labels[k] = v
		}
	}

	return labels
}

func (p *CPU) report(lastError error, lastProcessErrors map[int]error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if lastError == nil {
		p.lastSuccessfulProfileStartedAt = p.lastProfileStartedAt
		p.lastProfileStartedAt = time.Now()
	}
	p.lastError = lastError
	p.lastProcessErrors = lastProcessErrors
}

type (
	// stackCountKey mirrors the struct in BPF program.
	// NOTICE: The memory layout and alignment of the struct currently matches the struct in BPF program.
	// However, keep in mind that Go compiler injects padding to align the struct fields to be a multiple of 8 bytes.
	// The Go spec says the address of a struct’s fields must be naturally aligned.
	// https://dave.cheney.net/2015/10/09/padding-is-hard
	// TODO(https://github.com/parca-dev/parca-agent/issues/207)
	stackCountKey struct {
		PID           uint32
		UserStackID   int32
		KernelStackID int32
	}
)

// obtainProfiles collects profiles from the BPF maps.
func (p *CPU) obtainProfiles(ctx context.Context) ([]*profiler.Profile, error) {
	var (
		kernelMapping = &profile.Mapping{
			File: kernelMappingFileName,
		}
		// All these are grouped by the group key, which happens to be a pid right now.
		allSamples      = map[profiler.PID]map[combinedStack]*profile.Sample{}
		sampleLocations = map[profiler.PID][]*profile.Location{}
		locations       = map[profiler.PID][]*profile.Location{}
		kernelLocations = map[profiler.PID][]*profile.Location{}
		userLocations   = map[profiler.PID][]*profile.Location{}
		locationIndices = map[profiler.PID]map[uint64]int{}
	)

	it := p.bpfMaps.counts.Iterator()
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

		pid := profiler.PID(key.PID)

		// Twice the stack depth because we have a user and a potential Kernel stack.
		// Read order matters, since we read from the key buffer.
		stack := combinedStack{}
		userErr := p.bpfMaps.readUserStack(key.UserStackID, &stack)
		if userErr != nil {
			p.metrics.failedStackReads.WithLabelValues("user").Inc()
			if errors.Is(userErr, errUnrecoverable) {
				return nil, userErr
			}
			if errors.Is(userErr, errUnwindFailed) {
				p.metrics.failedStackUnwindingAttempts.WithLabelValues("user").Inc()
			}
			if errors.Is(userErr, errUnwindFailed) {
				p.metrics.missingStacks.WithLabelValues("user").Inc()
			}
		}
		kernelErr := p.bpfMaps.readKernelStack(key.KernelStackID, &stack)
		if kernelErr != nil {
			p.metrics.failedStackReads.WithLabelValues("kernel").Inc()
			if errors.Is(kernelErr, errUnrecoverable) {
				return nil, kernelErr
			}
			if errors.Is(kernelErr, errUnwindFailed) {
				p.metrics.failedStackUnwindingAttempts.WithLabelValues("kernel").Inc()
			}
			if errors.Is(kernelErr, errUnwindFailed) {
				p.metrics.missingStacks.WithLabelValues("kernel").Inc()
			}
		}

		if userErr != nil && kernelErr != nil {
			// Both stacks are missing. Nothing to do.
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

		_, ok := allSamples[pid]
		if !ok {
			// We haven't seen this pid yet.
			allSamples[pid] = map[combinedStack]*profile.Sample{}
		}

		sample, ok := allSamples[pid][stack]
		if ok {
			// We already have a sample with this stack trace, so just add
			// it to the previous one.
			sample.Value[0] += int64(value)
			continue
		}

		sampleLocations[pid] = []*profile.Location{}

		_, ok = userLocations[pid]
		if !ok {
			userLocations[pid] = []*profile.Location{}
		}
		_, ok = locationIndices[pid]
		if !ok {
			locationIndices[pid] = map[uint64]int{}
		}

		// Collect Kernel stack trace samples.
		for _, addr := range stack[stackDepth:] {
			if addr != uint64(0) {
				locationIndex, ok := locationIndices[pid][addr]
				if !ok {
					locationIndex = len(locations[pid])
					l := &profile.Location{
						ID:      uint64(locationIndex + 1),
						Address: addr,
						Mapping: kernelMapping,
					}
					locations[pid] = append(locations[pid], l)
					kernelLocations[pid] = append(kernelLocations[pid], l)
					locationIndices[pid][addr] = locationIndex
				}
				sampleLocations[pid] = append(
					sampleLocations[pid],
					locations[pid][locationIndex],
				)
			}
		}

		// Collect User stack trace samples.
		for _, addr := range stack[:stackDepth] {
			if addr != uint64(0) {
				locationIndex, ok := locationIndices[pid][addr]
				if !ok {
					locationIndex = len(locations[pid])

					m, err := p.processMappings.PIDAddrMapping(int(key.PID), addr)
					if err != nil {
						if !errors.Is(err, process.ErrNotFound) {
							level.Debug(p.logger).Log("msg", "failed to get process mapping", "pid", pid, "address", addr, "err", err)
						}
					}

					l := &profile.Location{
						ID: uint64(locationIndex + 1),
						// Try to normalize the address for a symbol for position-independent code.
						Address: p.normalizer.Normalize(int(key.PID), m, addr),
						Mapping: m,
					}

					locations[pid] = append(locations[pid], l)
					userLocations[pid] = append(userLocations[pid], l)
					locationIndices[pid][addr] = locationIndex
				}
				sampleLocations[pid] = append(
					sampleLocations[pid],
					locations[pid][locationIndex],
				)
			}
		}

		sample = &profile.Sample{
			Value:    []int64{int64(value)},
			Location: sampleLocations[pid],
		}
		allSamples[pid][stack] = sample
	}
	if it.Err() != nil {
		return nil, fmt.Errorf("failed iterator: %w", it.Err())
	}
	if err := p.bpfMaps.clean(); err != nil {
		level.Warn(p.logger).Log("msg", "failed to clean BPF maps", "err", err)
	}

	profiles := []*profiler.Profile{}
	for pid, stackSamples := range allSamples {
		samples := make([]*profile.Sample, 0, len(stackSamples))
		for _, s := range stackSamples {
			samples = append(samples, s)
		}
		profiles = append(profiles, &profiler.Profile{
			PID:             pid,
			Samples:         samples,
			Locations:       locations[pid],
			KernelLocations: kernelLocations[pid],
			UserLocations:   userLocations[pid],
			UserMappings:    p.processMappings.MappingsForPID(int(pid)),
			KernelMapping:   kernelMapping,
		})
	}
	return profiles, nil
}
