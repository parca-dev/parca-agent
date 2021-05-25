package main

import (
	"C"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/pprof/profile"
	"golang.org/x/sys/unix"

	"github.com/polarsignals/polarsignals-agent/byteorder"
	"github.com/polarsignals/polarsignals-agent/k8s"
	"github.com/polarsignals/polarsignals-agent/ksym"
)
import "github.com/polarsignals/polarsignals-agent/maps"

//go:embed dist/polarsignals-agent.bpf.o
var bpfObj []byte

const (
	stackDepth       = 20
	doubleStackDepth = 40
)

type ContainerProfiler struct {
	logger    log.Logger
	ksymCache *ksym.KsymCache
	target    k8s.ContainerDefinition
	cancel    func()

	mtx         *sync.RWMutex
	lastProfile *profile.Profile

	pidMappingFileCache *maps.PidMappingFileCache
}

func NewContainerProfiler(
	logger log.Logger,
	ksymCache *ksym.KsymCache,
	target k8s.ContainerDefinition,
) *ContainerProfiler {
	return &ContainerProfiler{
		logger:              logger,
		ksymCache:           ksymCache,
		target:              target,
		mtx:                 &sync.RWMutex{},
		pidMappingFileCache: maps.NewPidMappingFileCache(logger),
	}
}

func (p *ContainerProfiler) ContainerName() string {
	return p.target.ContainerName
}

func (p *ContainerProfiler) Stop() {
	level.Debug(p.logger).Log("msg", "stopping container profiler")
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *ContainerProfiler) LastProfile() *profile.Profile {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastProfile
}

func (p *ContainerProfiler) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting container profiler")
	ctx, p.cancel = context.WithCancel(ctx)

	m, err := bpf.NewModuleFromBuffer(bpfObj, "polarsignals")
	if err != nil {
		return err
	}
	defer m.Close()

	err = m.BPFLoadObject()
	if err != nil {
		return err
	}

	// This is so hacky I'm thoroughly ashamed of it, but cgroup setups are so
	// inconsistent that this is a "works most of the time" heuristic.
	parts := strings.Split(p.target.CgroupV1, "/")
	kubepodsFound := false
	keep := []string{}
	for _, part := range parts {
		if strings.HasPrefix(part, "kubepods") {
			kubepodsFound = true
		}
		if kubepodsFound {
			keep = append(keep, part)
		}
	}

	cgroup, err := os.Open("/sys/fs/cgroup/perf_event/" + strings.Join(keep, "/"))
	if err != nil {
		return err
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
			return err
		}

		prog, err := m.GetProgram("do_sample")
		if err != nil {
			return err
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

	duration := time.Second * 10
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	for {
		prof := &profile.Profile{
			SampleType: []*profile.ValueType{{
				Type: "samples",
				Unit: "count",
			}},
			TimeNanos:     time.Now().UnixNano(),
			DurationNanos: int64(duration),

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

		// 2 uint64 1 for PID and 1 for Addr
		locations := []*profile.Location{}
		kernelLocations := []*profile.Location{}
		kernelAddresses := map[uint64]struct{}{}
		locationIndices := map[[2]uint64]int{}
		samples := map[[doubleStackDepth]uint64]*profile.Sample{}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

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

			valueBytes, err := counts.GetValue(keyBytes)
			if err != nil {
				return fmt.Errorf("get count value: %w", err)
			}
			value := byteOrder.Uint64(valueBytes)

			stackBytes, err := stackTraces.GetValue(userStackID)
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
				stackBytes, err = stackTraces.GetValue(kernelStackID)
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

		prof.Mapping = mapping.AllMappings()
		prof.Location = locations
		//seenMapping := map[string]*profile.Mapping{}
		//for _, l := range prof.Location {
		//	if l.Mapping != nil {
		//		seenMapping[mappingKey(l.Mapping)] = l.Mapping
		//	}
		//}

		kernelSymbols, err := p.ksymCache.Resolve(kernelAddresses)
		for _, l := range kernelLocations {
			if err != nil {
				fmt.Errorf("resolve kernel symbols: %w", err)
			}
			kernelFunction, ok := kernelFunctions[l.Address]
			if !ok {
				name := kernelSymbols[l.Address]
				if name == "" {
					if p.target.ContainerName == "busy-cpu" {
						fmt.Printf("Addresses: %#+v\n", kernelAddresses)
						fmt.Printf("Cache: %#+v\n", p.ksymCache)
					}
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

		// Fix potentially re-created mappings that are identical to previous
		// ones.
		//for _, l := range prof.Location {
		//	if l.Mapping != nil {
		//		l.Mapping = seenMapping[mappingKey(l.Mapping)]
		//	}
		//}

		kernelMapping.ID = uint64(len(prof.Mapping)) + 1
		prof.Mapping = append(prof.Mapping, kernelMapping)

		profileCopy := prof.Copy()
		p.mtx.Lock()
		p.lastProfile = profileCopy
		p.mtx.Unlock()

		// BPF iterators need the previous value to iterate to the next, so we
		// can only delete the "previous" item once we've already iterated to
		// the next.

		it = stackTraces.Iterator()
		var prev []byte = nil
		for it.Next() {
			if prev != nil {
				err := stackTraces.DeleteKey(prev)
				if err != nil {
					level.Warn(p.logger).Log("msg", "failed to delete stack trace", "err", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := stackTraces.DeleteKey(prev)
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to delete stack trace", "err", err)
			}
		}

		it = counts.Iterator()
		prev = nil
		for it.Next() {
			if prev != nil {
				err := counts.DeleteKey(prev)
				if err != nil {
					level.Warn(p.logger).Log("msg", "failed to delete count", "err", err)
				}
			}

			key := it.Key()
			prev = make([]byte, len(key))
			copy(prev, key)
		}
		if prev != nil {
			err := counts.DeleteKey(prev)
			if err != nil {
				level.Warn(p.logger).Log("msg", "failed to delete count", "err", err)
			}
		}
	}
}

func mappingKey(m *profile.Mapping) string {
	return fmt.Sprintf("%x:%x:%x:%s:%s", m.Start, m.Limit, m.Offset, m.File, m.BuildID)
}
