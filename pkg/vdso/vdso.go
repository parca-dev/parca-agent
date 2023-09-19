// Copyright 2023 The Parca Authors
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

package vdso

import (
	"fmt"

	"github.com/parca-dev/parca/pkg/symbol/symbolsearcher"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/kernel"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/process"
)

type metrics struct {
	success            prometheus.Counter
	failure            prometheus.Counter
	errorNotFound      prometheus.Counter
	errorNormalization prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	lookup := promauto.With(reg).NewCounterVec(
		prometheus.CounterOpts{
			Name: "parca_agent_profiler_vdso_lookup_total",
			Help: "Total number of operations of looking up vdso symbols.",
		},
		[]string{"result"},
	)
	lookupErrors := promauto.With(reg).NewCounterVec(
		prometheus.CounterOpts{
			Name: "parca_agent_profiler_vdso_lookup_errors_total",
			Help: "Total number of errors while looking up vdso symbols.",
		},
		[]string{"type"},
	)
	m := &metrics{
		success:            lookup.WithLabelValues("success"),
		failure:            lookup.WithLabelValues("error"),
		errorNotFound:      lookupErrors.WithLabelValues("not_found"),
		errorNormalization: lookupErrors.WithLabelValues("normalization"),
	}
	return m
}

type NoopCache struct{}

func (NoopCache) Resolve(*process.Mapping, uint64) (string, error) { return "", nil }

type Cache struct {
	metrics *metrics

	searcher symbolsearcher.Searcher
	f        string
}

func NewCache(reg prometheus.Registerer, objFilePool *objectfile.Pool) (*Cache, error) {
	// This file is not present on all systems. It's an optimization.
	path, err := kernel.FindVDSO()
	if err != nil {
		return nil, err
	}

	obj, err := objFilePool.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open elf file: %s, err: %w", path, err)
	}

	ef, err := obj.ELF()
	if err != nil {
		return nil, fmt.Errorf("failed to get elf file: %s, err: %w", path, err)
	}

	// output of readelf --dyn-syms vdso.so:
	//  Num:    Value          Size Type    Bind   Vis      Ndx Name
	//     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
	//     1: ffffffffff700354     0 SECTION LOCAL  DEFAULT    7
	//     2: ffffffffff700700  1389 FUNC    WEAK   DEFAULT   13 clock_gettime@@LINUX_2.6
	//     3: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  ABS LINUX_2.6
	//     4: ffffffffff700c70   734 FUNC    GLOBAL DEFAULT   13 __vdso_gettimeofday@@LINUX_2.6
	//     5: ffffffffff700f70    61 FUNC    GLOBAL DEFAULT   13 __vdso_getcpu@@LINUX_2.6
	//     6: ffffffffff700c70   734 FUNC    WEAK   DEFAULT   13 gettimeofday@@LINUX_2.6
	//     7: ffffffffff700f50    22 FUNC    WEAK   DEFAULT   13 time@@LINUX_2.6
	//     8: ffffffffff700f70    61 FUNC    WEAK   DEFAULT   13 getcpu@@LINUX_2.6
	//     9: ffffffffff700700  1389 FUNC    GLOBAL DEFAULT   13 __vdso_clock_gettime@@LINUX_2.6
	//    10: ffffffffff700f50    22 FUNC    GLOBAL DEFAULT   13 __vdso_time@@LINUX_2.6
	syms, err := ef.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	return &Cache{newMetrics(reg), symbolsearcher.New(syms), path}, nil
}

func (c *Cache) Resolve(m *process.Mapping, addr uint64) (string, error) {
	addr, err := m.Normalize(addr)
	if err != nil {
		c.metrics.failure.Inc()
		c.metrics.errorNormalization.Inc()
	}

	sym, err := c.searcher.Search(addr)
	if err != nil {
		c.metrics.failure.Inc()
		c.metrics.errorNotFound.Inc()
		return "", err
	}

	c.metrics.success.Inc()
	return sym, nil
}
