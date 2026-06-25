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

// Package metricexport provides a small OTLP metrics egress path for
// parca-agent. It is deliberately generic: a Producer collects gauge/sum
// metrics in the background and renders them into a pmetric.MetricSlice on
// demand, and the Exporter periodically batches every producer's output into a
// single OTLP ExportMetricsServiceRequest and ships it over an existing
// remote-store gRPC connection (the same one used for profiles).
//
// The GPU metrics collector (package gpumetrics) is the first Producer, but
// nothing here is GPU-specific — any subsystem that wants to emit metrics to
// the remote store can register a Producer.
package metricexport

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

// Producer collects metrics in the background (Collect, blocking until ctx is
// cancelled) and renders the metrics accumulated so far into ms (Produce,
// called periodically by the Exporter). Implementations must be safe for
// Produce and Collect to run concurrently.
type Producer interface {
	// Produce appends the metrics collected since the last call to ms.
	Produce(ms pmetric.MetricSlice) error
	// Collect runs the background collection loop until ctx is cancelled.
	Collect(ctx context.Context) error
}

// ProducerConfig pairs a Producer with the OTLP instrumentation scope its
// metrics are reported under.
type ProducerConfig struct {
	Producer  Producer
	ScopeName string
}

// Exporter periodically renders all registered producers into a single OTLP
// metrics request and sends it over conn.
type Exporter struct {
	client        pmetricotlp.GRPCClient
	interval      time.Duration
	producers     []ProducerConfig
	resourceAttrs map[string]any
}

// NewExporter builds an Exporter that ships metrics over conn (typically the
// agent's existing remote-store connection) every interval. resourceAttrs are
// attached to the OTLP Resource (e.g. {"node": <node name>}).
func NewExporter(conn *grpc.ClientConn, interval time.Duration, resourceAttrs map[string]any) *Exporter {
	return &Exporter{
		client:        pmetricotlp.NewGRPCClient(conn),
		interval:      interval,
		resourceAttrs: resourceAttrs,
	}
}

// AddProducer registers a producer. Call before Run/Collect.
func (e *Exporter) AddProducer(p ProducerConfig) {
	e.producers = append(e.producers, p)
}

func (e *Exporter) report(ctx context.Context) error {
	m := pmetric.NewMetrics()
	r := m.ResourceMetrics().AppendEmpty()
	if err := r.Resource().Attributes().FromRaw(e.resourceAttrs); err != nil {
		return err
	}
	for _, p := range e.producers {
		s := r.ScopeMetrics().AppendEmpty()
		s.Scope().SetName(p.ScopeName)
		if err := p.Producer.Produce(s.Metrics()); err != nil {
			log.WithError(err).WithField("scope", p.ScopeName).Warn("metrics producer failed to produce")
		}
	}

	dpc := m.DataPointCount()
	if dpc == 0 {
		return nil
	}

	req := pmetricotlp.NewExportRequestFromMetrics(m)
	start := time.Now()
	resp, err := e.client.Export(ctx, req)
	if err != nil {
		return fmt.Errorf("otlp metrics export failed: %w", err)
	}
	if ps := resp.PartialSuccess(); ps.RejectedDataPoints() > 0 || ps.ErrorMessage() != "" {
		log.WithFields(log.Fields{
			"rejected": ps.RejectedDataPoints(),
			"message":  ps.ErrorMessage(),
		}).Warn("otlp metrics partial success")
	}
	log.WithFields(log.Fields{
		"data_points": dpc,
		"duration":    time.Since(start),
	}).Debug("gpu metrics export succeeded")
	return nil
}

// Run starts every producer's background collection loop and the periodic
// export loop, blocking until ctx is cancelled or a fatal error occurs.
func (e *Exporter) Run(ctx context.Context) error {
	if len(e.producers) == 0 {
		return errors.New("metricexport: no producers configured")
	}
	log.WithField("producers", len(e.producers)).Info("starting otlp metrics exporter")

	g, ctx := errgroup.WithContext(ctx)

	// Background collection loops, one per producer.
	for _, p := range e.producers {
		g.Go(func() error {
			return p.Producer.Collect(ctx)
		})
	}

	// Periodic export loop.
	g.Go(func() error {
		tick := time.NewTicker(e.interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
				if err := e.report(ctx); err != nil {
					// Don't tear the agent down over a transient export
					// failure; log and keep collecting.
					log.WithError(err).Warn("failed to send otlp gpu metrics")
				}
				tick.Reset(addJitter(e.interval, 0.2))
			}
		}
	})

	return g.Wait()
}

// addJitter adds +/- jitter (jitter is [0..1]) to baseDuration.
// Originally copied from go.opentelemetry.io/ebpf-profiler.
func addJitter(baseDuration time.Duration, jitter float64) time.Duration {
	if jitter < 0.0 || jitter > 1.0 {
		return baseDuration
	}
	//nolint:gosec
	return time.Duration((1 + jitter - 2*jitter*rand.Float64()) * float64(baseDuration))
}
