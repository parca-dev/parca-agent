//go:build linux

package probes

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed bpf
var bpfFS embed.FS

// probeEventSize is the on-the-wire size of `struct probe_event` from
// probe.bpf.c. Keep the Go decoder in sync if the C struct changes.
const probeEventSize = 40

// rawProbeEvent is the layout produced by bpf/probe.bpf.c. Decoded from
// little-endian raw bytes; do not change field order without updating
// the C struct.
type rawProbeEvent struct {
	KtimeNs uint64
	PID     uint32
	TID     uint32
	Comm    [16]byte
	SpecID  uint32
	_       uint32
}

func decodeEvent(b []byte, e *rawProbeEvent) error {
	if len(b) < probeEventSize {
		return fmt.Errorf("ringbuf record too short: %d bytes", len(b))
	}
	e.KtimeNs = binary.LittleEndian.Uint64(b[0:8])
	e.PID = binary.LittleEndian.Uint32(b[8:12])
	e.TID = binary.LittleEndian.Uint32(b[12:16])
	copy(e.Comm[:], b[16:32])
	e.SpecID = binary.LittleEndian.Uint32(b[32:36])
	return nil
}

// loadedBPF holds the resources owned by a loaded BPF program.
type loadedBPF struct {
	coll       *ebpf.Collection
	prog       *ebpf.Program
	ringbufMap *ebpf.Map
	reader     *ringbuf.Reader
}

func (l *loadedBPF) Close() error {
	if l == nil {
		return nil
	}
	var firstErr error
	if l.reader != nil {
		if err := l.reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return firstErr
}

func loadBPF() (*loadedBPF, error) {
	blob, err := readEmbeddedBPF()
	if err != nil {
		return nil, err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("load BPF collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create BPF collection: %w", err)
	}

	prog, ok := coll.Programs["probe_event"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing program 'probe_event'")
	}
	rbMap, ok := coll.Maps["probe_events"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing map 'probe_events'")
	}

	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	return &loadedBPF{
		coll:       coll,
		prog:       prog,
		ringbufMap: rbMap,
		reader:     reader,
	}, nil
}

func readEmbeddedBPF() ([]byte, error) {
	name := fmt.Sprintf("bpf/probe.bpf.%s", runtime.GOARCH)
	blob, err := bpfFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("embedded BPF object %s not found: run `make probes-bpf` (%w)", name, err)
	}
	if len(blob) < 4 || string(blob[:4]) != "\x7fELF" {
		return nil, fmt.Errorf("embedded BPF object %s is not a valid ELF (size=%d): run `make probes-bpf`", name, len(blob))
	}
	return blob, nil
}
