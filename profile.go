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
	"os/exec"
	"path"
	"runtime"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/conprof/conprof/pkg/store/storepb"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/pprof/profile"
	"github.com/thanos-io/thanos/pkg/store/labelpb"
	"golang.org/x/sys/unix"

	"github.com/parca-dev/parca-agent/byteorder"
	"github.com/parca-dev/parca-agent/ksym"
	"github.com/parca-dev/parca-agent/maps"
)
import (
	"hash/fnv"
	"math"
	"sync"

	"google.golang.org/grpc"
)

//go:embed dist/parca-agent.bpf.o
var bpfObj []byte

var seps = []byte{'\xff'}

const (
	stackDepth        = 20
	doubleStackDepth  = 40
	profilingDuration = time.Second * 10
)

type Record struct {
	Labels  []labelpb.Label
	Profile *profile.Profile
}

type CgroupProfilingTarget interface {
	PerfEventCgroupPath() string
	Labels() []labelpb.Label
}

type NoopSymbolStoreClient struct{}

func (c *NoopSymbolStoreClient) Exists(ctx context.Context, buildID string) (bool, error) {
	return true, nil
}
func (c *NoopSymbolStoreClient) Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error) {
	return 0, nil
}

func NewNoopSymbolStoreClient() SymbolStoreClient {
	return &NoopSymbolStoreClient{}
}

type NoopWritableProfileStoreClient struct{}

func (c *NoopWritableProfileStoreClient) Exists(ctx context.Context, buildID string) (bool, error) {
	return true, nil
}
func (c *NoopWritableProfileStoreClient) Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error) {
	return 0, nil
}

func NewNoopWritableProfileStoreClient() storepb.WritableProfileStoreClient {
	return &NoopWritableProfileStoreClient{}
}

func (c *NoopWritableProfileStoreClient) Write(ctx context.Context, in *storepb.WriteRequest, opts ...grpc.CallOption) (*storepb.WriteResponse, error) {
	return &storepb.WriteResponse{}, nil
}

type SymbolStoreClient interface {
	Exists(ctx context.Context, buildID string) (bool, error)
	Upload(ctx context.Context, buildID string, f io.Reader) (uint64, error)
}

type CgroupProfiler struct {
	logger    log.Logger
	ksymCache *ksym.KsymCache
	target    CgroupProfilingTarget
	sink      func(Record)
	cancel    func()

	pidMappingFileCache *maps.PidMappingFileCache
	writeClient         storepb.WritableProfileStoreClient
	symbolClient        SymbolStoreClient

	mtx                *sync.RWMutex
	lastProfileTakenAt time.Time
	lastError          error
}

func NewCgroupProfiler(
	logger log.Logger,
	ksymCache *ksym.KsymCache,
	writeClient storepb.WritableProfileStoreClient,
	symbolClient SymbolStoreClient,
	target CgroupProfilingTarget,
	sink func(Record),
) *CgroupProfiler {
	return &CgroupProfiler{
		logger:              logger,
		ksymCache:           ksymCache,
		target:              target,
		sink:                sink,
		pidMappingFileCache: maps.NewPidMappingFileCache(logger),
		writeClient:         writeClient,
		symbolClient:        symbolClient,
		mtx:                 &sync.RWMutex{},
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

func (p *CgroupProfiler) Labels() []labelpb.Label {
	return append(p.target.Labels(), labelpb.Label{
		Name:  "__name__",
		Value: "cpu_samples",
	})
}

func (p *CgroupProfiler) Run(ctx context.Context) error {
	level.Debug(p.logger).Log("msg", "starting cgroup profiler")
	ctx, p.cancel = context.WithCancel(ctx)

	m, err := bpf.NewModuleFromBuffer(bpfObj, "parca")
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

	ticker := time.NewTicker(profilingDuration)
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
		DurationNanos: int64(profilingDuration),

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

	var buildIDFiles map[string]string
	prof.Mapping, buildIDFiles = mapping.AllMappings()
	prof.Location = locations

	kernelSymbols, err := p.ksymCache.Resolve(kernelAddresses)
	for _, l := range kernelLocations {
		if err != nil {
			fmt.Errorf("resolve kernel symbols: %w", err)
		}
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

	p.ensureDebugSymbolsUploaded(ctx, buildIDFiles)

	buf := bytes.NewBuffer(nil)
	err = prof.Write(buf)
	if err != nil {
		return err
	}
	labels := p.Labels()
	_, err = p.writeClient.Write(ctx, &storepb.WriteRequest{
		ProfileSeries: []storepb.ProfileSeries{{
			Labels: labels,
			Samples: []storepb.Sample{{
				Timestamp: timestampFromTime(now),
				Value:     buf.Bytes(),
			}},
		}},
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

	return nil
}

func probabilisticSampling(ratio float64, labels []labelpb.Label) bool {
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

func (p *CgroupProfiler) ensureDebugSymbolsUploaded(ctx context.Context, buildIDFiles map[string]string) {
	for buildID, file := range buildIDFiles {
		exists, err := p.symbolClient.Exists(ctx, buildID)
		if err != nil {
			level.Error(p.logger).Log("msg", "failed to check whether build ID symbol exists", "err", err)
			continue
		}
		if !exists {
			debugFile := path.Join("/tmp", buildID)
			cmd := exec.Command("objcopy", "--only-keep-debug", file, debugFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			defer os.Remove(debugFile)
			if err != nil {
				level.Error(p.logger).Log("msg", "failed to extract debug infos", "buildid", buildID, "originalfile", file, "err", err)
				continue
			}

			f, err := os.Open(debugFile)
			if err != nil {
				level.Error(p.logger).Log("msg", "failed open build ID symbol source", "buildid", buildID, "originalfile", file, "err", err)
				continue
			}
			_, err = p.symbolClient.Upload(ctx, buildID, f)
			if err != nil {
				level.Error(p.logger).Log("msg", "failed upload build ID symbol source", "buildid", buildID, "originalfile", file, "err", err)
				continue
			}
		}
	}
}

func mappingKey(m *profile.Mapping) string {
	return fmt.Sprintf("%x:%x:%x:%s:%s", m.Start, m.Limit, m.Offset, m.File, m.BuildID)
}

func timestampFromTime(t time.Time) int64 {
	return t.Unix()*1000 + int64(t.Nanosecond())/int64(time.Millisecond)
}
