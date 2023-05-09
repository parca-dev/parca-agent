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
)

// normalizer is a normalizer that converts memory addresses to position-independent addresses.
type normalizer struct {
	logger log.Logger
	// normalizationEnabled indicates whether the profiler has to
	// normalize sampled addresses for PIC/PIE (position independent code/executable).
	normalizationEnabled  bool
	normalizationAttempts *prometheus.CounterVec
}

// NewNormalizer creates a new AddressNormalizer.
func NewNormalizer(logger log.Logger, reg prometheus.Registerer, normalizationEnabled bool) *normalizer {
	return &normalizer{
		logger:               logger,
		normalizationEnabled: normalizationEnabled,
		normalizationAttempts: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Name:        "parca_agent_profiler_normalization_attempts_total",
				Help:        "Total number of attempts normalizing frame addresses.",
				ConstLabels: map[string]string{"type": "cpu"},
			},
			[]string{"status"},
		),
	}
}

// Normalize calculates the base addresses of a position-independent binary and normalizes captured locations accordingly.
func (n *normalizer) Normalize(m *process.Mapping, addr uint64) (uint64, error) {
	if !n.normalizationEnabled {
		return addr, nil
	}

	if m == nil {
		return 0, errors.New("mapping is nil")
	}
	if m.Pathname == "" {
		return 0, errors.New("mapping pathname is empty")
	}

	if m.Pathname == "[vdso]" {
		// vdso is a special mapping that is handled by vdso package.
		// Only on symbolization time.
		return addr, nil
	}

	// Transform the address using calculated base address for the binary.
	normalizedAddr, err := m.Normalize(addr)
	if err != nil {
		n.normalizationAttempts.WithLabelValues(lvError).Inc()
		return 0, fmt.Errorf("failed to get normalized address from object file: %w", err)
	}
	n.normalizationAttempts.WithLabelValues(lvSuccess).Inc()
	return normalizedAddr, nil
}
