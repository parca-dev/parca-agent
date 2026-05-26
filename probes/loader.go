//go:build linux

package probes

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed bpf
var bpfFS embed.FS

// probeEventSize is the on-the-wire size of `struct probe_event` from
// probe.bpf.c. Keep the Go decoder in sync if the C struct changes.
const probeEventSize = 48

// rawProbeEvent is the layout produced by bpf/probe.bpf.c. Decoded from
// little-endian raw bytes; do not change field order without updating
// the C struct.
type rawProbeEvent struct {
	KtimeNs    uint64
	DurationNs uint64
	PID        uint32
	TID        uint32
	Comm       [16]byte
	SpecID     uint32
	IsMain     uint32
}

func decodeEvent(b []byte, e *rawProbeEvent) error {
	if len(b) < probeEventSize {
		return fmt.Errorf("ringbuf record too short: %d bytes", len(b))
	}
	e.KtimeNs = binary.LittleEndian.Uint64(b[0:8])
	e.DurationNs = binary.LittleEndian.Uint64(b[8:16])
	e.PID = binary.LittleEndian.Uint32(b[16:20])
	e.TID = binary.LittleEndian.Uint32(b[20:24])
	copy(e.Comm[:], b[24:40])
	e.SpecID = binary.LittleEndian.Uint32(b[40:44])
	e.IsMain = binary.LittleEndian.Uint32(b[44:48])
	return nil
}

// loadedBPF holds the resources owned by a loaded BPF program.
type loadedBPF struct {
	coll       *ebpf.Collection
	progEntry  *ebpf.Program
	progExit   *ebpf.Program
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

	progEntry, ok := coll.Programs["probe_entry"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing program 'probe_entry'")
	}
	progExit, ok := coll.Programs["probe_exit"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing program 'probe_exit'")
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
		progEntry:  progEntry,
		progExit:   progExit,
		ringbufMap: rbMap,
		reader:     reader,
	}, nil
}

func readEmbeddedBPF() ([]byte, error) {
	// One object covers every arch: clang -target bpf is host-independent
	// and our program uses no arch-specific macros (PT_REGS_*, etc.). If
	// that changes, this lookup will need a runtime.GOARCH-keyed suffix.
	const name = "bpf/probe.bpf.o"
	blob, err := bpfFS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("embedded BPF object %s not found: run `make probes-bpf` (%w)", name, err)
	}
	if len(blob) < 4 || string(blob[:4]) != "\x7fELF" {
		return nil, fmt.Errorf("embedded BPF object %s is not a valid ELF (size=%d): run `make probes-bpf`", name, len(blob))
	}
	return blob, nil
}
