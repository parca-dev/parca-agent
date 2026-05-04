//go:build linux

package probes

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// attachReq is enqueued by OnExecutable for the worker goroutine to process.
type attachReq struct {
	filePath string
	fileID   libpf.FileID
	specs    []ProbeSpec
}

// attacher owns the state for matching new binaries against the spec list and
// attaching uprobes to them on a worker goroutine. The hot-path callback only
// holds the mutex long enough to dedupe by FileID and run regexes.
type attacher struct {
	prog  *ebpf.Program
	specs []ProbeSpec

	mu       sync.Mutex
	attached map[libpf.FileID]struct{}
	links    map[libpf.FileID][]link.Link

	queue chan attachReq
}

func newAttacher(prog *ebpf.Program, specs []ProbeSpec, queueDepth int) *attacher {
	return &attacher{
		prog:     prog,
		specs:    specs,
		attached: make(map[libpf.FileID]struct{}),
		links:    make(map[libpf.FileID][]link.Link),
		queue:    make(chan attachReq, queueDepth),
	}
}

// OnExecutable is the cheap-path callback invoked from the otel ebpf-profiler
// reporter goroutine. It must not block: dedupe, regex-match, and enqueue.
// All disk I/O happens in attachWorker.
func (a *attacher) OnExecutable(filePath string, fileID libpf.FileID) {
	a.mu.Lock()
	if _, seen := a.attached[fileID]; seen {
		a.mu.Unlock()
		return
	}
	a.attached[fileID] = struct{}{}
	a.mu.Unlock()

	var matched []ProbeSpec
	for _, s := range a.specs {
		if s.FileMatchRE.MatchString(filePath) {
			matched = append(matched, s)
		}
	}
	if len(matched) == 0 {
		return
	}

	select {
	case a.queue <- attachReq{filePath: filePath, fileID: fileID, specs: matched}:
	default:
		// Queue full: log and forget. We've already marked this fileID as
		// "seen" so we won't try again, which is fine for v1 — the user
		// can restart with a smaller probe-config or a deeper queue.
		log.Warnf("probes: attach queue full, dropping %s (fileID=%s)", filePath, fileID.StringNoQuotes())
	}
}

// run is the attachWorker goroutine. Returns when the queue is drained after
// ctx is cancelled.
func (a *attacher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-a.queue:
			a.handle(req)
		}
	}
}

func (a *attacher) handle(req attachReq) {
	ex, err := link.OpenExecutable(req.filePath)
	if err != nil {
		log.Warnf("probes: open executable %s: %v", req.filePath, err)
		return
	}

	var newLinks []link.Link
	for _, s := range req.specs {
		l, err := ex.Uprobe(s.Symbol, a.prog, &link.UprobeOptions{
			Cookie: uint64(s.SpecID) << 32,
			PID:    0,
		})
		if err != nil {
			log.Warnf("probes: attach %s @ %s: %v", s.Symbol, req.filePath, err)
			continue
		}
		newLinks = append(newLinks, l)
		log.Debugf("probes: attached %s @ %s (spec_id=%d)", s.Symbol, req.filePath, s.SpecID)
	}
	if len(newLinks) == 0 {
		return
	}

	a.mu.Lock()
	a.links[req.fileID] = append(a.links[req.fileID], newLinks...)
	a.mu.Unlock()
}

// closeAllLinks tears down every attached uprobe link. Called from
// service.Close.
func (a *attacher) closeAllLinks() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for fid, links := range a.links {
		for _, l := range links {
			if err := l.Close(); err != nil {
				log.Warnf("probes: close link for fileID=%s: %v", fid.StringNoQuotes(), err)
			}
		}
	}
	a.links = nil
}
