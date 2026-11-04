// Copyright 2026 The Parca Authors
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

package reporter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/parca-dev/oomprof/oomprof"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"google.golang.org/grpc"

	"github.com/parca-dev/parca-agent/internal/log"
	"github.com/parca-dev/parca-agent/reporter/metadata"
)

const oomprofExportTimeout = 10 * time.Second

// OOMProfOTLPSink exports oomprof samples as OTLP/profiles as soon as they
// arrive. It serves the supervising parent process, which watches the agent
// itself: when the agent is OOM-killed there is no reporter left to batch the
// profile, and the parent exits soon after, so nothing is buffered.
type OOMProfOTLPSink struct {
	client       pprofileotlp.GRPCClient
	exportOpts   []grpc.CallOption
	reportAllocs bool

	mu       sync.Mutex
	builder  *pprofileBuilder
	lastSent map[uint32]time.Time
}

var _ oomprof.Reporter = (*OOMProfOTLPSink)(nil)

// NewOOMProfOTLPSink returns a sink exporting over conn.
func NewOOMProfOTLPSink(conn *grpc.ClientConn, nodeName string, externalLabels map[string]string,
	reportAllocs bool, exportOpts ...grpc.CallOption,
) (*OOMProfOTLPSink, error) {
	if conn == nil {
		return nil, errors.New("OOMProf OTLP sink requires a gRPC connection")
	}
	// Memory frames carry their build ID beside them, so the executable
	// cache is never consulted; it only satisfies the builder.
	execs, err := lru.NewSynced[libpf.FileID, metadata.ExecInfo](1, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	return &OOMProfOTLPSink{
		client:       pprofileotlp.NewGRPCClient(conn),
		exportOpts:   exportOpts,
		reportAllocs: reportAllocs,
		builder:      newPprofileBuilder(execs, nodeName, metadata.InKubernetes(), externalLabels),
		lastSent:     make(map[uint32]time.Time),
	}, nil
}

// SampleEvents satisfies oomprof.Reporter. It converts and exports one batch
// before returning.
func (s *OOMProfOTLPSink) SampleEvents(memSamples []oomprof.Sample, meta oomprof.SampleMeta) error {
	if len(memSamples) == 0 {
		return nil
	}
	res := resourceLabels{
		PID:            int64(meta.PID),
		ExecutablePath: meta.ExecutablePath,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.builder.addMemorySamples(res, nil, memSamples, meta, s.reportAllocs)
	count := s.builder.SampleCount()
	if count == 0 {
		return nil
	}
	at := time.Unix(0, int64(meta.Timestamp))
	profiles := s.builder.Build(at, at)

	ctx, cancel := context.WithTimeout(context.Background(), oomprofExportTimeout)
	defer cancel()
	resp, err := s.client.Export(ctx, pprofileotlp.NewExportRequestFromProfiles(profiles), s.exportOpts...)
	s.lastSent[meta.PID] = time.Now()
	if err != nil {
		return fmt.Errorf("export %d OOM samples for PID %d: %w", count, meta.PID, err)
	}
	if ps := resp.PartialSuccess(); ps.ErrorMessage() != "" {
		log.Warnf("OOMProf OTLP partial success: %s", ps.ErrorMessage())
	}
	log.Infof("Sent OOM profile with %d samples for PID %d (%s)", count, meta.PID, meta.Comm)
	return nil
}

// WaitForProfile blocks until a profile for pid has been sent and no further
// batch for it has arrived for quiet, or until timeout. oomprof reads a
// victim's profile after the kernel has started killing it, so a parent that
// exits as soon as its child does would otherwise lose the profile. It reports
// whether any batch for pid was sent.
func (s *OOMProfOTLPSink) WaitForProfile(pid uint32, quiet, timeout time.Duration) bool {
	const poll = 50 * time.Millisecond
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		last, sent := s.lastSent[pid]
		s.mu.Unlock()

		now := time.Now()
		if sent && now.Sub(last) >= quiet {
			return true
		}
		if now.After(deadline) {
			return sent
		}
		time.Sleep(poll)
	}
}
