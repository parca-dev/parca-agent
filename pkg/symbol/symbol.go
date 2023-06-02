// Copyright 2022-2023 The Parca Authors
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
//

package symbol

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/perf"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

type SymbolResolver interface {
	Resolve(addrs map[uint64]struct{}) (map[uint64]string, error)
}

type PerfMapFinder interface {
	MapForPID(pid int) (*perf.Map, error)
}

type VDSOResolver interface {
	Resolve(addr uint64, m *process.Mapping) (string, error)
}

const (
	lvSuccess = "success"
	lvFail    = "fail"
)

type metrics struct {
	symbolizeAttempts *prometheus.CounterVec
	vdsoAttempts      *prometheus.CounterVec
	jitAttempts       *prometheus.CounterVec
	kernelAttempts    *prometheus.CounterVec

	symbolizeDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		symbolizeAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_symbolize_attempts_total",
				Help: "Total number of attempts to symbolize a stack.",
			},
			[]string{"result"},
		),
		symbolizeDuration: promauto.With(reg).NewHistogram(
			prometheus.HistogramOpts{
				Name:                        "parca_agent_profiler_symbolize_duration_seconds",
				Help:                        "The duration it takes to symbolize and convert to pprof",
				ConstLabels:                 map[string]string{"type": "cpu"},
				NativeHistogramBucketFactor: 1.1,
			},
		),
		vdsoAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_symbolize_vdso_attempts_total",
				Help: "Total number of attempts to symbolize a vdso stack.",
			},
			[]string{"result"},
		),
		jitAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_symbolize_jit_attempts_total",
				Help: "Total number of attempts to symbolize a jit stack.",
			},
			[]string{"result"},
		),
		kernelAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_symbolize_kernel_attempts_total",
				Help: "Total number of attempts to symbolize a kernel stack.",
			},
			[]string{"result"},
		),
	}
	m.symbolizeAttempts.WithLabelValues(lvSuccess)
	m.symbolizeAttempts.WithLabelValues(lvFail)
	m.jitAttempts.WithLabelValues(lvSuccess)
	m.jitAttempts.WithLabelValues(lvFail)
	m.jitAttempts.WithLabelValues(lvSuccess)
	m.kernelAttempts.WithLabelValues(lvFail)
	m.kernelAttempts.WithLabelValues(lvSuccess)
	return m
}

// Symbolizer helps to resolve symbols for the stacks to obtain stacks using information on the host.
type Symbolizer struct {
	logger  log.Logger
	metrics *metrics

	disableJIT bool

	perfCache PerfMapFinder
	ksymCache SymbolResolver
	vdsoCache VDSOResolver
}

func NewSymbolizer(logger log.Logger, reg prometheus.Registerer, perfCache PerfMapFinder, ksymCache SymbolResolver, vdsoCache VDSOResolver, disableJIT bool) *Symbolizer {
	return &Symbolizer{
		logger:  logger,
		metrics: newMetrics(reg),

		disableJIT: disableJIT,

		// TODO(kakkoyun): Reconsider these caches. Do we really need all?
		perfCache: perfCache,
		ksymCache: ksymCache,
		vdsoCache: vdsoCache,
	}
}

func (s *Symbolizer) Symbolize(prof *profiler.Profile) error {
	start := time.Now()
	defer func() {
		s.metrics.symbolizeDuration.Observe(time.Since(start).Seconds())
	}()

	var result *multierror.Error
	kernelFunctions, err := s.resolveKernelFunctions(prof.KernelLocations)
	if err != nil {
		s.metrics.kernelAttempts.WithLabelValues(lvFail).Inc()
		result = multierror.Append(result, fmt.Errorf("failed to resolve kernel functions: %w", err))
	} else {
		s.metrics.kernelAttempts.WithLabelValues(lvSuccess).Inc()
		for _, f := range kernelFunctions {
			// TODO(kakkoyun): Move the ID logic top pprof converter.
			f.ID = uint64(len(prof.Functions)) + 1
			prof.Functions = append(prof.Functions, f)
		}
	}

	if s.vdsoCache != nil {
		var vdsoResult *multierror.Error
		for _, l := range prof.UserLocations {
			if l.Mapping.Pathname == "[vdso]" {
				name, err := s.vdsoCache.Resolve(l.Address, l.Mapping)
				if err != nil {
					vdsoResult = multierror.Append(result, fmt.Errorf("failed to resolve vdso functions: %w", err))
					continue
				}
				f := profiler.NewFunction(name)
				l.AddLine(f)
				prof.Functions = append(prof.Functions, f)
			}
		}
		if vdsoResult != nil {
			s.metrics.vdsoAttempts.WithLabelValues(lvFail).Inc()
			result = multierror.Append(result, vdsoResult)
		} else {
			s.metrics.vdsoAttempts.WithLabelValues(lvSuccess).Inc()
		}
	}

	// JIT symbolization is disabled, so we can skip the rest.
	if s.disableJIT {
		return result.ErrorOrNil()
	}

	pid := prof.ID.PID
	userJITedFunctions, err := s.resolveJITedFunctions(pid, prof.UserLocations)
	if err != nil {
		s.metrics.jitAttempts.WithLabelValues(lvFail).Inc()
		// Often some processes exit before symbols can be looked up.
		// We also expect only a minority of processes to have a JIT and produce the perf map.
		if errors.Is(err, perf.ErrProcNotFound) || errors.Is(err, perf.ErrPerfMapNotFound) {
			return nil
		}
		result = multierror.Append(result, fmt.Errorf("failed to resolve user JITed functions: %w", err))
		return result.ErrorOrNil()
	}
	if len(userJITedFunctions) == 0 {
		return result.ErrorOrNil()
	}

	s.metrics.jitAttempts.WithLabelValues(lvSuccess).Inc()
	for _, f := range userJITedFunctions {
		// TODO(kakkoyun): Move the ID logic top pprof converter.
		f.ID = uint64(len(prof.Functions)) + 1
		prof.Functions = append(prof.Functions, f)
	}

	if err := result.ErrorOrNil(); err != nil {
		s.metrics.symbolizeAttempts.WithLabelValues(lvFail).Inc()
		return err
	}
	s.metrics.symbolizeAttempts.WithLabelValues(lvSuccess).Inc()
	return nil
}

// resolveJITedFunctions resolves the just-in-time compiled functions using the perf map.
func (s *Symbolizer) resolveJITedFunctions(pid profiler.PID, locations []*profiler.Location) (map[uint64]*profiler.Function, error) {
	perfMap, err := s.perfCache.MapForPID(int(pid))
	if err != nil {
		return nil, err
	}
	addrFunc := map[uint64]*profiler.Function{}
	for _, loc := range locations {
		jitFunction, ok := addrFunc[loc.Address]
		if !ok {
			sym, err := perfMap.Lookup(loc.Address)
			if err != nil {
				level.Debug(s.logger).Log("msg", "failed to lookup JIT symbol", "pid", pid, "address", loc.Address, "err", err)
				continue
			}
			jitFunction = profiler.NewFunction(sym)
			addrFunc[loc.Address] = jitFunction
		}
		if jitFunction != nil {
			loc.AddLine(jitFunction)
		}
	}
	return addrFunc, nil
}

// resolveKernelFunctions resolves kernel function names.
func (s *Symbolizer) resolveKernelFunctions(kernelLocations []*profiler.Location) (map[uint64]*profiler.Function, error) {
	kernelAddresses := map[uint64]struct{}{}
	for _, kloc := range kernelLocations {
		kernelAddresses[kloc.Address] = struct{}{}
	}
	kernelSymbols, err := s.ksymCache.Resolve(kernelAddresses)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel symbols: %w", err)
	}
	addrFunc := map[uint64]*profiler.Function{}
	for _, kloc := range kernelLocations {
		kernelFunction, ok := addrFunc[kloc.Address]
		if !ok {
			name := kernelSymbols[kloc.Address]
			if name == "" {
				name = "not found"
			}
			kernelFunction = profiler.NewFunction(name)
			addrFunc[kloc.Address] = kernelFunction
		}
		if kernelFunction != nil {
			kloc.AddLine(kernelFunction)
		}
	}
	return addrFunc, nil
}
