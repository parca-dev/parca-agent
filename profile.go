package main

import (
	"C"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
	"github.com/go-kit/kit/log"
	"golang.org/x/sys/unix"

	"github.com/polarsignals/polarsignals-agent/k8s"
)
import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/go-kit/kit/log/level"
	"github.com/polarsignals/polarsignals-agent/ksym"
)

//go:embed dist/polarsignals-agent.bpf.o
var bpfObj []byte

var (
	byteOrder  binary.ByteOrder
	stackDepth = 20
)

// In lack of binary.HostEndian ...
func init() {
	byteOrder = determineHostByteOrder()
}

// GetHostByteOrder returns the current byte-order.
func GetHostByteOrder() binary.ByteOrder {
	return byteOrder
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

type Sample struct {
	Pid                uint32
	UserStack          []uint64
	KernelStack        []uint64
	KernelStackStrings []string
	Value              uint64
}

type Profile struct {
	TimeTaken     time.Time
	Duration      time.Duration
	Samples       []*Sample
	MissingStacks int
}

type ContainerProfiler struct {
	logger log.Logger
	target k8s.ContainerDefinition
	cancel func()

	mtx         *sync.RWMutex
	lastProfile *Profile
}

func NewContainerProfiler(logger log.Logger, target k8s.ContainerDefinition) *ContainerProfiler {
	return &ContainerProfiler{
		logger: logger,
		target: target,
		mtx:    &sync.RWMutex{},
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

func (p *ContainerProfiler) WriteTo(w io.Writer) error {
	p.mtx.RLock()
	profile := p.lastProfile
	p.mtx.RUnlock()

	if profile == nil {
		return nil
	}

	fmt.Fprintln(w, "Taken At:", profile.TimeTaken.String())
	fmt.Fprintln(w, "Duration:", profile.Duration.String())
	fmt.Fprintln(w, "MissingStacks:", profile.MissingStacks)
	fmt.Fprintln(w)
	for _, s := range profile.Samples {
		fmt.Fprintln(w, "PID:", s.Pid)
		fmt.Fprintf(w, "%#+v\n", s.UserStack)
		fmt.Fprintf(w, "%#+v\n", s.KernelStack)
		fmt.Fprintf(w, "%#+v\n", s.KernelStackStrings)
		fmt.Fprintln(w, "Value:", s.Value)
	}
	return nil
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
		profile := &Profile{
			TimeTaken: time.Now(),
			Duration:  duration,
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		//has_collision := false

		keySize := 4 + // PID
			4 + // UserStackID
			4 // KernelStackID
		it := counts.Iter(keySize)
		byteOrder := GetHostByteOrder()
		for it.Next() {
			sample := &Sample{}
			// This byte slice is only valid for this iteration, so it must be
			// copied if we want to do anything with it outside of this loop.
			keyBytes := it.Key()

			r := bytes.NewBuffer(keyBytes)

			pidBytes := make([]byte, 4)
			if _, err := io.ReadFull(r, pidBytes); err != nil {
				return fmt.Errorf("read pid bytes: %w", err)
			}
			sample.Pid = byteOrder.Uint32(pidBytes)

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

			valueBytes, err := counts.GetValue(keyBytes, 8)
			if err != nil {
				return fmt.Errorf("get count value: %w", err)
			}
			sample.Value = byteOrder.Uint64(valueBytes)

			stackBytes, err := stackTraces.GetValue(userStackID, 8*stackDepth)
			if err != nil {
				profile.MissingStacks++
				continue
			}
			stack := make([]uint64, stackDepth)
			err = binary.Read(bytes.NewBuffer(stackBytes), byteOrder, stack)
			if err != nil {
				return fmt.Errorf("read stack trace: %w", err)
			}
			for _, addr := range stack {
				if addr != uint64(0) {
					sample.UserStack = append(sample.UserStack, addr)
				}
			}

			if kernelStackID >= 0 {
				stackBytes, err = stackTraces.GetValue(kernelStackID, 8*stackDepth)
				if err != nil {
					profile.MissingStacks++
					continue
				}

				stack = make([]uint64, stackDepth)
				err = binary.Read(bytes.NewBuffer(stackBytes), byteOrder, stack)
				if err != nil {
					return fmt.Errorf("read stack trace: %w", err)
				}

				for _, addr := range stack {
					if addr != uint64(0) {
						sample.KernelStack = append(sample.KernelStack, addr)
						sym, err := ksym.Resolve(addr)
						if err != nil && !errors.Is(err, ksym.FunctionNotFoundError) {
							return err
						}

						sample.KernelStackStrings = append(sample.KernelStackStrings, sym.Name)
					}
				}
			}
			profile.Samples = append(profile.Samples, sample)
		}
		if it.Err() != nil {
			return fmt.Errorf("failed iterator: %w", it.Err())
		}

		p.mtx.Lock()
		p.lastProfile = profile
		p.mtx.Unlock()

		//TODO(brancz): Need to cleanup maps after each iteration.
		//if err := stackTraces.DeleteAll(); err != nil {
		//	log.Fatal(err)
		//}
		//if err := counts.DeleteAll(); err != nil {
		//	log.Fatal(err)
		//}
	}
}
