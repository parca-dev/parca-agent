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

package address

import (
	"errors"
	"fmt"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/process"
)

const (
	lvError   = "error"
	lvSuccess = "success"

	lvErrMappingNil      = "mapping_nil"
	lvErrMappingEmpty    = "mapping_empty"
	lvErrAddrOutOfRange  = "addr_out_of_range"
	lvErrBaseCalculation = "base_calculation"
	lvErrUnknown         = "unknown"
)

type metrics struct {
	normalization       *prometheus.CounterVec
	normalizationErrors *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		normalization: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_normalization_total",
				Help: "Total number of operations of normalizing frame addresses.",
			},
			[]string{"result"},
		),
		normalizationErrors: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name: "parca_agent_profiler_normalization_errors_total",
				Help: "Total number of errors while normalizing frame addresses.",
			},
			[]string{"type"},
		),
	}
	m.normalization.WithLabelValues(lvSuccess)
	m.normalization.WithLabelValues(lvError)
	m.normalizationErrors.WithLabelValues(lvErrMappingNil)
	m.normalizationErrors.WithLabelValues(lvErrMappingEmpty)
	m.normalizationErrors.WithLabelValues(lvErrAddrOutOfRange)
	m.normalizationErrors.WithLabelValues(lvErrBaseCalculation)
	m.normalizationErrors.WithLabelValues(lvErrUnknown)
	return m
}

// normalizer is a normalizer that converts memory addresses to position-independent addresses.
type normalizer struct {
	logger  log.Logger
	metrics *metrics
	// normalizationEnabled indicates whether the profiler has to
	// normalize sampled addresses for PIC/PIE (position independent code/executable).
	normalizationEnabled bool
}

// NewNormalizer creates a new AddressNormalizer.
func NewNormalizer(logger log.Logger, reg prometheus.Registerer, normalizationEnabled bool) *normalizer {
	return &normalizer{
		logger:               logger,
		metrics:              newMetrics(reg),
		normalizationEnabled: normalizationEnabled,
	}
}

// Normalize calculates the base addresses of a position-independent binary and normalizes captured locations accordingly.
func (n *normalizer) Normalize(m *process.Mapping, addr uint64) (uint64, error) {
	if !n.normalizationEnabled {
		return addr, nil
	}

	if m == nil {
		n.metrics.normalization.WithLabelValues(lvError).Inc()
		n.metrics.normalizationErrors.WithLabelValues(lvErrMappingNil).Inc()
		return 0, errors.New("mapping is nil")
	}

	// Do not normalize JIT sections.
	//
	// TODO: Improve this, as some JITs might actually create files.
	// TODO: Add NoopNormalizer for JITs.
	if m.Pathname == "" {
		n.metrics.normalization.WithLabelValues(lvError).Inc()
		n.metrics.normalizationErrors.WithLabelValues(lvErrMappingEmpty).Inc()
		return addr, nil
	}
	if m.Pathname == "[vdso]" {
		// vdso is a special mapping that is handled by vdso package.
		// Only on symbolization time.
		return addr, nil
	}

	// Transform the address using calculated base address for the binary.
	normalizedAddr, err := m.Normalize(addr)
	if err != nil {
		n.metrics.normalization.WithLabelValues(lvError).Inc()
		var addrErr *process.AddressOutOfRangeError
		switch {
		case errors.As(err, &addrErr):
			n.metrics.normalizationErrors.WithLabelValues(lvErrAddrOutOfRange).Inc()
		case errors.Is(err, process.ErrBaseAddressCannotCalculated):
			n.metrics.normalizationErrors.WithLabelValues(lvErrBaseCalculation).Inc()
		default:
			n.metrics.normalizationErrors.WithLabelValues(lvErrUnknown).Inc()
		}
		return 0, fmt.Errorf("failed to get normalized address from object file: %w", err)
	}
	n.metrics.normalization.WithLabelValues(lvSuccess).Inc()
	return normalizedAddr, nil
}
