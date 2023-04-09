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

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"
	"github.com/hashicorp/go-multierror"

	"github.com/parca-dev/parca-agent/pkg/perf"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/vdso"
)

type SymbolCache interface {
	Resolve(addrs map[uint64]struct{}) (map[uint64]string, error)
}

type PerfCache interface {
	MapForPID(pid int) (*perf.Map, error)
}

// Symbolizer helps to resolve symbols for the stacks to obtain stacks using information on the host.
type Symbolizer struct {
	logger log.Logger

	normalizer profiler.Normalizer
	perfCache  PerfCache
	ksymCache  SymbolCache
	vdsoCache  *vdso.Cache

	disableJIT bool
	// isNormalizationEnabled indicates whether the profiler has to
	// normalize sampled addresses for PIC/PIE (position independent code/executable).
	// The agent never normalizes addresses found in kernel stack traces,
	// but it could normalize user stack traces (vdso, JIT).
	// When resolving JIT symbols, the addresses mustn't be normalized, see #1537.
	isNormalizationEnabled bool
}

func NewSymbolizer(logger log.Logger, normalizer profiler.Normalizer, perfCache PerfCache, ksymCache SymbolCache, vdsoCache *vdso.Cache, disableJIT, enableNormalization bool) *Symbolizer {
	return &Symbolizer{
		logger: logger,

		normalizer: normalizer,
		perfCache:  perfCache,
		ksymCache:  ksymCache,
		vdsoCache:  vdsoCache,

		disableJIT:             disableJIT,
		isNormalizationEnabled: enableNormalization,
	}
}

// Symbolize resolves kernel, vdso, and JIT function names.
func (s *Symbolizer) Symbolize(prof *profiler.Profile) error {
	var result *multierror.Error
	kernelFunctions, err := s.resolveKernelFunctions(prof.KernelLocations)
	if err != nil {
		result = multierror.Append(result, fmt.Errorf("failed to resolve kernel functions: %w", err))
	} else {
		for _, f := range kernelFunctions {
			f.ID = uint64(len(prof.Functions)) + 1
			prof.Functions = append(prof.Functions, f)
		}
	}

	pid := prof.ID.PID

	if s.vdsoCache != nil {
		for _, l := range prof.UserLocations {
			if l.Mapping.File != "[vdso]" {
				continue
			}

			// In case the agent runs with a disabled normalization,
			// the vdso sampled address must be normalized
			// before attempting to resolve a function name.
			addr := l.Address
			if !s.isNormalizationEnabled {
				normalizedAddress, err := s.normalizer.Normalize(int(pid), l.Mapping, addr)
				if err != nil {
					level.Debug(s.logger).Log("msg", "failed to normalize vdso address", "pid", pid, "address", addr, "err", err)
					continue
				}

				addr = normalizedAddress
			}

			name, err := s.vdsoCache.Resolve(addr, l.Mapping)
			if err != nil {
				result = multierror.Append(result, fmt.Errorf("failed to resolve vdso functions: %w", err))
				continue
			}
			f := &profile.Function{
				ID:   uint64(len(prof.Functions) + 1),
				Name: name,
			}
			prof.Functions = append(prof.Functions, f)
			l.Line = []profile.Line{
				{
					Function: f,
					Line:     0,
				},
			}
		}
	}

	// JIT symbolization is disabled, so we can skip the rest.
	if s.disableJIT {
		return result.ErrorOrNil()
	}

	userJITedFunctions, err := s.resolveJITedFunctions(pid, prof.UserLocations)
	if err != nil {
		// Often some processes exit before symbols can be looked up.
		// We also expect only a minority of processes to have a JIT and produce the perf map.
		if errors.Is(err, perf.ErrProcNotFound) || errors.Is(err, perf.ErrPerfMapNotFound) {
			return nil
		}
		result = multierror.Append(result, fmt.Errorf("failed to resolve user JITed functions: %w", err))
		return result.ErrorOrNil()
	}

	for _, f := range userJITedFunctions {
		f.ID = uint64(len(prof.Functions)) + 1
		prof.Functions = append(prof.Functions, f)
	}
	return result.ErrorOrNil()
}

// resolveJITedFunctions resolves the just-in-time compiled functions using the perf map.
func (s *Symbolizer) resolveJITedFunctions(pid profiler.PID, locations []*profile.Location) (map[uint64]*profile.Function, error) {
	perfMap, err := s.perfCache.MapForPID(int(pid))
	if err != nil {
		return nil, err
	}
	addrFunc := map[uint64]*profile.Function{}
	for _, loc := range locations {
		jitFunction, ok := addrFunc[loc.Address]
		if !ok {
			sym, err := perfMap.Lookup(loc.Address)
			if err != nil {
				level.Debug(s.logger).Log("msg", "failed to lookup JIT symbol", "pid", pid, "address", loc.Address, "err", err)
				continue
			}
			jitFunction = &profile.Function{Name: sym}
			addrFunc[loc.Address] = jitFunction
		}
		if jitFunction != nil {
			loc.Line = []profile.Line{{Function: jitFunction}}
		}
	}
	return addrFunc, nil
}

// resolveKernelFunctions resolves kernel function names.
func (s *Symbolizer) resolveKernelFunctions(kernelLocations []*profile.Location) (map[uint64]*profile.Function, error) {
	kernelAddresses := map[uint64]struct{}{}
	for _, kloc := range kernelLocations {
		kernelAddresses[kloc.Address] = struct{}{}
	}
	kernelSymbols, err := s.ksymCache.Resolve(kernelAddresses)
	if err != nil {
		return nil, fmt.Errorf("resolve kernel symbols: %w", err)
	}
	addrFunc := map[uint64]*profile.Function{}
	for _, kloc := range kernelLocations {
		kernelFunction, ok := addrFunc[kloc.Address]
		if !ok {
			name := kernelSymbols[kloc.Address]
			if name == "" {
				name = "not found"
			}
			kernelFunction = &profile.Function{
				Name: name,
			}
			addrFunc[kloc.Address] = kernelFunction
		}
		if kernelFunction != nil {
			kloc.Line = []profile.Line{{Function: kernelFunction}}
		}
	}
	return addrFunc, nil
}
