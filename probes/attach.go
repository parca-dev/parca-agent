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
// attaching paired entry/exit uprobes to them on a worker goroutine. The
// hot-path callback only holds the mutex long enough to dedupe by FileID and
// run regexes.
type attacher struct {
	progEntry *ebpf.Program
	progExit  *ebpf.Program
	specs     []ProbeSpec

	mu       sync.Mutex
	attached map[libpf.FileID]struct{}
	links    map[libpf.FileID][]link.Link

	queue chan attachReq
}

func newAttacher(progEntry, progExit *ebpf.Program, specs []ProbeSpec, queueDepth int) *attacher {
	return &attacher{
		progEntry: progEntry,
		progExit:  progExit,
		specs:     specs,
		attached:  make(map[libpf.FileID]struct{}),
		links:     make(map[libpf.FileID][]link.Link),
		queue:     make(chan attachReq, queueDepth),
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
		log.Debugf("probes: received %s (fileID=%s) -- no spec matched", filePath, fileID.StringNoQuotes())
		return
	}
	log.Debugf("probes: received %s (fileID=%s) -- %d spec(s) matched", filePath, fileID.StringNoQuotes(), len(matched))

	select {
	case a.queue <- attachReq{filePath: filePath, fileID: fileID, specs: matched}:
	default:
		// Queue full: log and forget. We've already marked this fileID as
		// "seen" so we won't try again, which is fine for v1 -- the user
		// can restart with a smaller probe-config or a deeper queue.
		log.Errorf("probes: attach queue full, dropping %s (fileID=%s)", filePath, fileID.StringNoQuotes())
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
		cookie := s.Cookie()

		entryLink, err := ex.Uprobe(s.EntrySymbol, a.progEntry, &link.UprobeOptions{
			Cookie: cookie,
			PID:    0,
		})
		if err != nil {
			log.Warnf("probes: attach entry %s @ %s: %v", s.EntrySymbol, req.filePath, err)
			continue
		}
		exitLink, err := ex.Uprobe(s.ExitSymbol, a.progExit, &link.UprobeOptions{
			Cookie: cookie,
			PID:    0,
		})
		if err != nil {
			log.Warnf("probes: attach exit %s @ %s: %v", s.ExitSymbol, req.filePath, err)
			// Roll back the entry uprobe so we don't have orphan stack pushes
			// with no exit to drain them.
			if cerr := entryLink.Close(); cerr != nil {
				log.Warnf("probes: rollback entry %s: %v", s.EntrySymbol, cerr)
			}
			continue
		}
		newLinks = append(newLinks, entryLink, exitLink)
		log.Debugf("probes: attached pair %s/%s @ %s (spec_id=%d, id=%s)",
			s.EntrySymbol, s.ExitSymbol, req.filePath, s.SpecID, s.ID)
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
