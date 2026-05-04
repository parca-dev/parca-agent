//go:build linux

package probes

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

// StartConfig is the small bag of parameters Service.Start needs in addition
// to the YAML probe-config path. All fields except ConfigPath are used only
// to populate resource attributes on outgoing log batches.
type StartConfig struct {
	ConfigPath     string // path to probe-config YAML; required
	Node           string // agent --node, used as host.name
	ServiceVersion string // build VCS revision; empty is fine
}

// Service owns the BPF program, the attach worker, the ringbuf drain loop,
// and the otel-arrow log stream. Construct with Start, tear down with Close.
type Service struct {
	cfg     StartConfig
	specs   []ProbeSpec
	specByID map[uint32]ProbeSpec

	// wallOffset converts kernel monotonic ns to ns since unix epoch:
	//   wall_ns = ktime_ns + wallOffset
	// Captured once at Start; we don't periodically resync (acceptable
	// drift for this v1 use case).
	wallOffset int64

	bpf      *loadedBPF
	attacher *attacher
	streamer *streamer

	events chan LogEvent

	rootCancel context.CancelFunc
	wg         sync.WaitGroup
}

// Start parses the YAML, loads the BPF program, and spawns the drain, stream,
// and attach goroutines. It does NOT attach any uprobes yet — those happen as
// OnExecutable is invoked by the reporter for each newly-observed binary.
func Start(ctx context.Context, cfg StartConfig, conn *grpc.ClientConn) (*Service, error) {
	if cfg.ConfigPath == "" {
		return nil, errors.New("probes: ConfigPath is required")
	}

	specs, err := LoadConfig(cfg.ConfigPath)
	if err != nil {
		return nil, err
	}
	specByID := make(map[uint32]ProbeSpec, len(specs))
	for _, s := range specs {
		specByID[s.SpecID] = s
	}
	log.Infof("probes: loaded %d probe specs from %s", len(specs), cfg.ConfigPath)

	wallOffset, err := captureWallOffset()
	if err != nil {
		return nil, fmt.Errorf("probes: capture wall offset: %w", err)
	}

	bpf, err := loadBPF()
	if err != nil {
		return nil, fmt.Errorf("probes: %w", err)
	}

	events := make(chan LogEvent, defaultEventQueue)

	att := newAttacher(bpf.prog, specs, 256)

	stream := newStreamer(conn, streamerOptions{
		ServiceName:    "parca-agent",
		ServiceVersion: cfg.ServiceVersion,
		HostName:       cfg.Node,
	}, events)

	rootCtx, cancel := context.WithCancel(ctx)

	s := &Service{
		cfg:        cfg,
		specs:      specs,
		specByID:   specByID,
		wallOffset: wallOffset,
		bpf:        bpf,
		attacher:   att,
		streamer:   stream,
		events:     events,
		rootCancel: cancel,
	}

	s.wg.Add(3)
	go func() {
		defer s.wg.Done()
		s.drainLoop(rootCtx)
	}()
	go func() {
		defer s.wg.Done()
		att.run(rootCtx)
	}()
	go func() {
		defer s.wg.Done()
		stream.run(rootCtx)
	}()

	return s, nil
}

// OnExecutable forwards a newly-observed binary to the attach worker. Safe
// to call from any goroutine; cheap on the hot path.
func (s *Service) OnExecutable(filePath string, fileID libpf.FileID) {
	if s == nil {
		return
	}
	s.attacher.OnExecutable(filePath, fileID)
}

// Close cancels the service's root context, waits for goroutines to drain,
// closes attached uprobe links, and releases BPF resources.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.rootCancel()
	s.wg.Wait()
	s.attacher.closeAllLinks()
	return s.bpf.Close()
}

// drainLoop reads from the BPF ringbuf, decodes events, looks up spec_id, and
// forwards LogEvents on the events channel. Closes the channel when the
// reader is closed.
func (s *Service) drainLoop(ctx context.Context) {
	defer close(s.events)

	var raw rawProbeEvent
	var dropped uint64
	logTick := time.NewTicker(30 * time.Second)
	defer logTick.Stop()

	for {
		// Cancellation is delivered by Close, which closes the ringbuf
		// reader and causes Read() to return an error.
		select {
		case <-ctx.Done():
			return
		case <-logTick.C:
			if dropped > 0 {
				log.Warnf("probes: dropped %d events (event channel full)", dropped)
				dropped = 0
			}
		default:
		}

		rec, err := s.bpf.reader.Read()
		if err != nil {
			if errors.Is(err, syscall.EBADF) || ctx.Err() != nil {
				return
			}
			log.Warnf("probes: ringbuf read: %v", err)
			return
		}
		if err := decodeEvent(rec.RawSample, &raw); err != nil {
			log.Warnf("probes: %v", err)
			continue
		}
		spec, ok := s.specByID[raw.SpecID]
		if !ok {
			log.Warnf("probes: unknown spec_id=%d in event", raw.SpecID)
			continue
		}

		ev := LogEvent{
			TimestampNs:         int64(raw.KtimeNs) + s.wallOffset,
			ObservedTimestampNs: time.Now().UnixNano(),
			PID:                 raw.PID,
			TID:                 raw.TID,
			Comm:                trimComm(raw.Comm[:]),
			SpecID:              raw.SpecID,
			ProbeName:           spec.Symbol,
		}

		select {
		case s.events <- ev:
		default:
			dropped++
		}
	}
}

func trimComm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// captureWallOffset returns wall - monotonic, in nanoseconds, sampled once.
// Adding this to a kernel ktime_ns reading yields a wall-clock unix-nano
// timestamp that aligns probe events with CPU samples (which the agent's
// reporter records using the same ktime->wall mapping).
func captureWallOffset() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	monoNs := ts.Sec*int64(time.Second) + int64(ts.Nsec)
	wallNs := time.Now().UnixNano()
	return wallNs - monoNs, nil
}
