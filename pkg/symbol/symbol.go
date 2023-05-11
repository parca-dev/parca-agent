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
	"github.com/hashicorp/go-multierror"

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

// Symbolizer helps to resolve symbols for the stacks to obtain stacks using information on the host.
type Symbolizer struct {
	logger log.Logger

	disableJIT bool

	perfCache PerfMapFinder
	ksymCache SymbolResolver
	vdsoCache VDSOResolver
}

func NewSymbolizer(logger log.Logger, perfCache PerfMapFinder, ksymCache SymbolResolver, vdsoCache VDSOResolver, disableJIT bool) *Symbolizer {
	return &Symbolizer{
		logger: logger,

		disableJIT: disableJIT,

		// TODO(kakkoyun): Reconsider these caches.
		perfCache: perfCache,
		ksymCache: ksymCache,
		vdsoCache: vdsoCache,
	}
}

func (s *Symbolizer) Symbolize(prof *profiler.Profile) error {
	var result *multierror.Error
	kernelFunctions, err := s.resolveKernelFunctions(prof.KernelLocations)
	if err != nil {
		result = multierror.Append(result, fmt.Errorf("failed to resolve kernel functions: %w", err))
	} else {
		for _, f := range kernelFunctions {
			// TODO(kakkoyun): Move the ID logic top pprof converter.
			f.ID = uint64(len(prof.Functions)) + 1
			prof.Functions = append(prof.Functions, f)
		}
	}

	if s.vdsoCache != nil {
		for _, l := range prof.UserLocations {
			// TODO(kakkoyun): Or Use Mapping.Pathname
			if l.Location.Mapping.File == "[vdso]" {
				name, err := s.vdsoCache.Resolve(l.Address, l.Mapping)
				if err != nil {
					result = multierror.Append(result, fmt.Errorf("failed to resolve vdso functions: %w", err))
					continue
				}
				f := profiler.NewFunction(name)
				l.AddLine(f)
				prof.Functions = append(prof.Functions, f)
			}
		}
	}

	// JIT symbolization is disabled, so we can skip the rest.
	if s.disableJIT {
		return result.ErrorOrNil()
	}

	pid := prof.ID.PID
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
		// TODO(kakkoyun): Move the ID logic top pprof converter.
		f.ID = uint64(len(prof.Functions)) + 1
		prof.Functions = append(prof.Functions, f)
	}
	return result.ErrorOrNil()
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
