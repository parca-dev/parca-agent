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

	perfCache PerfCache
	ksymCache SymbolCache
}

func NewSymbolizer(logger log.Logger, perfCache PerfCache, ksymCache SymbolCache) *Symbolizer {
	return &Symbolizer{
		logger: logger,

		perfCache: perfCache,
		ksymCache: ksymCache,
	}
}

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
	userJITedFunctions, err := s.resolveJITedFunctions(pid, prof.UserLocations)
	if err != nil {
		// Often some processes exit before symbols can be looked up.
		// We also expect only a minority of processes to have a JIT and produce the perf map.
		if errors.Is(err, perf.ErrProcStatusNotFound) || errors.Is(err, perf.ErrPerfMapNotFound) {
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
