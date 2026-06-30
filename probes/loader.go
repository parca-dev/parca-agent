//go:build linux

package probes

import (
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

// loadedBPF holds the resources owned by a loaded BPF program. The
// `objs` struct is the bpf2go-generated container for the maps and
// programs in bpf/probe.bpf.c.
type loadedBPF struct {
	objs   probeObjects
	reader *ringbuf.Reader
}

func (l *loadedBPF) Close() error {
	if l == nil {
		return nil
	}
	var firstErr error
	if l.reader != nil {
		if err := l.reader.Close(); err != nil {
			firstErr = err
		}
	}
	if err := l.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func loadBPF() (*loadedBPF, error) {
	var l loadedBPF
	if err := loadProbeObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load probe BPF objects: %w", err)
	}
	reader, err := ringbuf.NewReader(l.objs.ProbeEvents)
	if err != nil {
		_ = l.objs.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	l.reader = reader
	return &l, nil
}
