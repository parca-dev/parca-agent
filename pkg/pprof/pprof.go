// Copyright 2023-2024 The Parca Authors
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

package pprof

import (
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	pprofprofile "github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/parca-dev/parca/pkg/normalizer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/js"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/perf"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profile"
	"github.com/parca-dev/parca-agent/pkg/symtab"
)

type VDSOSymbolizer interface {
	Resolve(m *process.Mapping, addr uint64) (string, error)
}

type Manager struct {
	logger  log.Logger
	metrics *converterMetrics

	ksym                    *ksym.Ksym
	vdsoSymbolizer          VDSOSymbolizer
	perfMapCache            *perf.PerfMapCache
	jitdumpCache            *perf.JITDumpCache
	disableJITSymbolization bool
}

func NewManager(
	logger log.Logger,
	reg prometheus.Registerer,
	ksym *ksym.Ksym,
	perfMapCache *perf.PerfMapCache,
	jitdumpCache *perf.JITDumpCache,
	vdsoSymbolizer VDSOSymbolizer,
	disableJITSymbolization bool,
) *Manager {
	return &Manager{
		logger:                  logger,
		metrics:                 newConverterMetrics(reg),
		ksym:                    ksym,
		perfMapCache:            perfMapCache,
		jitdumpCache:            jitdumpCache,
		vdsoSymbolizer:          vdsoSymbolizer,
		disableJITSymbolization: disableJITSymbolization,
	}
}

type Converter struct {
	m      *Manager
	logger log.Logger

	// We already have the perf map cache but it Stats() the perf map on every
	// cache retrieval, but we only want to do that once per conversion.
	cachedPerfMap    *symtab.FileReader
	cachedPerfMapErr error

	// If the key is unchanged, then it's impossible to have evicted the value,
	// therefore it's safe to use the file reader from the previous read. In
	// practice there is usually no more than 1 jitdump per process anyway.
	cachedJITDumpKey string
	cachedJITDump    *symtab.FileReader
	cachedJITDumpErr error

	functionIndex            map[functionKey]*pprofprofile.Function
	addrLocationIndex        map[uint64]*pprofprofile.Location
	perfmapLocationIndex     map[string]*pprofprofile.Location
	jitdumpLocationIndex     map[string]*pprofprofile.Location
	kernelLocationIndex      map[string]*pprofprofile.Location
	interpreterLocationIndex map[uint32]*pprofprofile.Location
	vdsoLocationIndex        map[string]*pprofprofile.Location

	pfs                    procfs.FS
	pid                    int
	mappings               []*process.Mapping
	kernelMapping          *pprofprofile.Mapping
	executableInfos        []*profilestorepb.ExecutableInfo
	interpreterMapping     *pprofprofile.Mapping
	interpreterSymbolTable profile.InterpreterSymbolTable

	threadNameCache map[int]string

	result *pprofprofile.Profile
}

func (m *Manager) NewConverter(
	pfs procfs.FS,
	pid int,
	mappings process.Mappings,
	captureTime time.Time,
	periodNS int64,
	interpreterSymbolTable profile.InterpreterSymbolTable,
) *Converter {
	pprofMappings := mappings.ConvertToPprof()
	kernelMapping := &pprofprofile.Mapping{
		ID:   uint64(len(pprofMappings)) + 1, // +1 because pprof uses 1-indexing to be able to differentiate from 0 (unset).
		File: "[kernel.kallsyms]",
	}
	pprofMappings = append(pprofMappings, kernelMapping)

	interpreterMapping := &pprofprofile.Mapping{
		ID:   uint64(len(pprofMappings)) + 1, // +1 because pprof uses 1-indexing to be able to differentiate from 0 (unset).
		File: "interpreter",
	}
	pprofMappings = append(pprofMappings, interpreterMapping)

	return &Converter{
		m:      m,
		logger: log.With(m.logger, "pid", pid),

		functionIndex:            map[functionKey]*pprofprofile.Function{},
		addrLocationIndex:        map[uint64]*pprofprofile.Location{},
		perfmapLocationIndex:     map[string]*pprofprofile.Location{},
		jitdumpLocationIndex:     map[string]*pprofprofile.Location{},
		kernelLocationIndex:      map[string]*pprofprofile.Location{},
		interpreterLocationIndex: map[uint32]*pprofprofile.Location{},
		vdsoLocationIndex:        map[string]*pprofprofile.Location{},

		pfs:                    pfs,
		pid:                    pid,
		mappings:               mappings,
		kernelMapping:          kernelMapping,
		executableInfos:        make([]*profilestorepb.ExecutableInfo, len(pprofMappings)),
		interpreterMapping:     interpreterMapping,
		interpreterSymbolTable: interpreterSymbolTable,

		threadNameCache: map[int]string{},

		result: &pprofprofile.Profile{
			TimeNanos:     captureTime.UnixNano(),
			DurationNanos: int64(time.Since(captureTime)),
			Period:        periodNS,
			SampleType: []*pprofprofile.ValueType{{
				Type: "samples",
				Unit: "count",
			}},
			// Sampling at 100Hz would be every 10 Million nanoseconds.
			PeriodType: &pprofprofile.ValueType{
				Type: "cpu",
				Unit: "nanoseconds",
			},
			Mapping: pprofMappings,
		},
	}
}

const (
	threadIDLabel   = "thread_id"
	threadNameLabel = "thread_name"
)

func isNonEmptyTraceID(traceID [16]byte) bool {
	for _, b := range traceID {
		if b != 0 {
			return true
		}
	}
	return false
}

// Convert converts a profile to a pprof profile. It is intended to only be
// used once.
func (c *Converter) Convert(ctx context.Context, rawData []profile.RawSample) (*pprofprofile.Profile, []*profilestorepb.ExecutableInfo, error) {
	kernelAddresses := map[uint64]struct{}{}
	for _, sample := range rawData {
		for _, addr := range sample.KernelStack {
			kernelAddresses[addr] = struct{}{}
		}
	}

	kernelSymbols, err := c.m.ksym.Resolve(kernelAddresses)
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to resolve kernel symbols skipping profile", "err", err)
		kernelSymbols = map[uint64]string{}
	}

	proc, err := c.pfs.Proc(c.pid)
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to get process info", "pid", c.pid, "err", err)
	}

	for _, sample := range rawData {
		pprofSample := &pprofprofile.Sample{
			Value:    []int64{int64(sample.Value)},
			Location: make([]*pprofprofile.Location, 0, len(sample.UserStack)+len(sample.KernelStack)),
			Label:    make(map[string][]string),
		}

		for _, addr := range sample.KernelStack {
			l := c.addKernelLocation(c.kernelMapping, kernelSymbols, addr)
			pprofSample.Location = append(pprofSample.Location, l)
		}

		for _, frameID := range sample.InterpreterStack {
			l := c.AddUnwinderInfoLocation(frameID)
			pprofSample.Location = append(pprofSample.Location, l)
		}

		failedToNormalize := false

		for _, addr := range sample.UserStack {
			mappingIndex := mappingForAddr(c.result.Mapping, addr)
			if mappingIndex == -1 {
				c.m.metrics.frameDrop.WithLabelValues(labelFrameDropReasonMappingNil).Inc()
				// Normalization will fail anyway, so we can skip this frame.
				continue
			}

			processMapping := c.mappings[mappingIndex]
			pprofMapping := c.result.Mapping[mappingIndex]
			switch {
			case pprofMapping.File == "[vdso]":
				pprofSample.Location = append(pprofSample.Location, c.addVDSOLocation(processMapping, pprofMapping, addr))
			case processMapping.NoFileMapping:
				pprofSample.Location = append(pprofSample.Location, c.addJITLocation(c.mappings, pprofMapping, addr))
			case processMapping.IsJITDump:
				pprofSample.Location = append(pprofSample.Location, c.addJITDumpLocation(pprofMapping, addr, pprofMapping.File))
			default:
				ei := c.addExecutableInfo(processMapping, addr)
				c.executableInfos[mappingIndex] = ei
				_, err := normalizer.NormalizeAddress(addr, ei, pprofMapping.Start, pprofMapping.Limit, pprofMapping.Offset)
				if err != nil {
					level.Debug(c.logger).Log("msg", "failed to normalize address", "addr", addr, "err", err)
					failedToNormalize = true
					break
				}
				pprofSample.Location = append(pprofSample.Location, c.addAddrLocation(pprofMapping, addr))
			}
		}

		if failedToNormalize {
			c.m.metrics.stackDrop.WithLabelValues(labelStackDropReasonNormalizationFailed).Inc()
			continue
		}

		pprofSample.Label[threadIDLabel] = append(pprofSample.Label[threadIDLabel], strconv.FormatUint(uint64(sample.TID), 10))
		threadName := c.threadName(proc, int(sample.TID))
		if threadName != "" {
			pprofSample.Label[threadNameLabel] = append(pprofSample.Label[threadNameLabel], threadName)
		}
		if isNonEmptyTraceID(sample.TraceID) {
			pprofSample.Label["trace_id"] = append(pprofSample.Label["trace_id"], hex.EncodeToString(sample.TraceID[:]))
		}

		c.result.Sample = append(c.result.Sample, pprofSample)
	}

	return c.result, c.executableInfos, nil
}

func mappingForAddr(mappings []*pprofprofile.Mapping, addr uint64) int {
	for i, m := range mappings {
		if m.Start <= addr && addr < m.Limit {
			return i
		}
	}
	return -1
}

func (c *Converter) addKernelLocation(
	m *pprofprofile.Mapping,
	kernelSymbols map[uint64]string,
	addr uint64,
) *pprofprofile.Location {
	kernelSymbol, ok := kernelSymbols[addr]
	if !ok {
		kernelSymbol = "not found"
	}

	if l, ok := c.kernelLocationIndex[kernelSymbol]; ok {
		return l
	}

	l := &pprofprofile.Location{
		ID:      uint64(len(c.result.Location)) + 1,
		Mapping: m,
		Line: []pprofprofile.Line{{
			Function: c.addFunction(kernelSymbol, ""),
		}},
	}

	c.kernelLocationIndex[kernelSymbol] = l
	c.result.Location = append(c.result.Location, l)

	return l
}

func (c *Converter) interpreterSymbol(frameID uint32) *profile.Function {
	interpreterSymbol, ok := c.interpreterSymbolTable[frameID]
	if !ok {
		return &profile.Function{Name: "<not found>"}
	}
	return interpreterSymbol
}

func (c *Converter) AddUnwinderInfoLocation(frameID uint64) *pprofprofile.Location {
	lineno := uint32(frameID >> 32)
	symbolID := uint32(frameID)

	interpreterSymbol := c.interpreterSymbol(symbolID)

	if l, ok := c.interpreterLocationIndex[symbolID]; ok {
		return l
	}

	l := &pprofprofile.Location{
		ID:      uint64(len(c.result.Location)) + 1,
		Mapping: c.interpreterMapping,
		Line: []pprofprofile.Line{{
			Function: c.addFunction(interpreterSymbol.FullName(), interpreterSymbol.Filename),
			Line:     int64(lineno),
		}},
	}

	c.interpreterLocationIndex[symbolID] = l
	c.result.Location = append(c.result.Location, l)
	return l
}

func (c *Converter) addVDSOLocation(
	processMapping *process.Mapping,
	m *pprofprofile.Mapping,
	addr uint64,
) *pprofprofile.Location {
	functionName, err := c.m.vdsoSymbolizer.Resolve(processMapping, addr)
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to symbolize VDSO address", "address", strconv.FormatUint(addr, 16), "err", err)
		functionName = "unknown"
	}

	if l, ok := c.vdsoLocationIndex[functionName]; ok {
		return l
	}

	l := &pprofprofile.Location{
		ID:      uint64(len(c.result.Location)) + 1,
		Mapping: m,
		Line: []pprofprofile.Line{{
			Function: c.addFunction(functionName, ""),
		}},
	}

	c.vdsoLocationIndex[functionName] = l
	c.result.Location = append(c.result.Location, l)

	return l
}

func (c *Converter) addExecutableInfo(
	processMapping *process.Mapping,
	addr uint64,
) *profilestorepb.ExecutableInfo {
	ei, err := processMapping.ExecutableInfo(addr)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		level.Debug(c.logger).Log("msg", "failed to get executable info", "address", strconv.FormatUint(addr, 16), "err", err)
	}

	return ei
}

func (c *Converter) addAddrLocation(m *pprofprofile.Mapping, addr uint64) *pprofprofile.Location {
	if l, ok := c.addrLocationIndex[addr]; ok {
		return l
	}

	l := &pprofprofile.Location{
		ID:      uint64(len(c.result.Location)) + 1,
		Mapping: m,
		Address: addr,
	}

	c.addrLocationIndex[addr] = l
	c.result.Location = append(c.result.Location, l)

	return l
}

func (c *Converter) addJITLocation(
	mappings process.Mappings,
	m *pprofprofile.Mapping,
	addr uint64,
) *pprofprofile.Location {
	if c.m.disableJITSymbolization {
		return c.addAddrLocation(m, addr)
	}

	// We have an address that does not have a backing file, therefore we first
	// try to symbolize using any of the mappings we've found to be jitdumps.
	// Unfortunately this is unspecified and different JITs do different
	// things. Eg. nodejs correctly annotates mappings with their backing
	// jitdump file, but Julia does not.
	for i, mapping := range mappings {
		if mapping.IsJITDump {
			if l := c.getJITDumpLocation(c.result.Mapping[i], addr, mapping.Pathname); l != nil {
				return l
			}
		}
	}

	perfMap, err := c.perfMap()
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to fetch perf map", "pid", c.pid, "err", err)
	}

	if perfMap == nil {
		return c.addAddrLocation(m, addr)
	}

	symbol, err := perfMap.Symbolize(addr)
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to lookup symbol for JITed address", "pid", c.pid, "address", strconv.FormatUint(addr, 16), "err", err)
		return c.addAddrLocation(m, addr)
	}

	if l, ok := c.perfmapLocationIndex[symbol]; ok {
		return l
	}

	l := c.locationFromSymbol(m, symbol)

	c.perfmapLocationIndex[symbol] = l
	c.result.Location = append(c.result.Location, l)
	return l
}

func (c *Converter) locationFromSymbol(m *pprofprofile.Mapping, symbol string) *pprofprofile.Location {
	if js.IsJsSymbol(symbol) {
		jsSymbol, err := js.ParseJsSymbol(symbol)
		if err == nil {
			return &pprofprofile.Location{
				ID:      uint64(len(c.result.Location)) + 1,
				Mapping: m,
				Line: []pprofprofile.Line{{
					Line:     int64(jsSymbol.LineNumber),
					Function: c.addFunction(jsSymbol.FunctionName, jsSymbol.File),
				}},
			}
		}
		// Always fallback to the default.
	}

	return &pprofprofile.Location{
		ID:      uint64(len(c.result.Location)) + 1,
		Mapping: m,
		Line: []pprofprofile.Line{{
			Function: c.addFunction(symbol, ""),
		}},
	}
}

func (c *Converter) perfMap() (*symtab.FileReader, error) {
	if c.cachedPerfMap != nil || c.cachedPerfMapErr != nil {
		return c.cachedPerfMap, c.cachedPerfMapErr
	}

	c.cachedPerfMap, c.cachedPerfMapErr = c.m.perfMapCache.PerfMapForPID(c.pid)
	return c.cachedPerfMap, c.cachedPerfMapErr
}

func (c *Converter) addJITDumpLocation(
	m *pprofprofile.Mapping,
	addr uint64,
	path string,
) *pprofprofile.Location {
	if c.m.disableJITSymbolization {
		return c.addAddrLocation(m, addr)
	}

	if l := c.getJITDumpLocation(m, addr, path); l != nil {
		return l
	}

	return c.addAddrLocation(m, addr)
}

func (c *Converter) getJITDumpLocation(
	m *pprofprofile.Mapping,
	addr uint64,
	path string,
) *pprofprofile.Location {
	jitdump, err := c.jitdump(path)
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to fetch jitdump", "pid", c.pid, "path", path, "err", err)
	}

	if jitdump == nil {
		return nil
	}

	symbol, err := jitdump.Symbolize(addr)
	if err != nil {
		return nil
	}

	if l, ok := c.jitdumpLocationIndex[symbol]; ok {
		return l
	}

	l := c.locationFromSymbol(m, symbol)

	c.jitdumpLocationIndex[symbol] = l
	c.result.Location = append(c.result.Location, l)
	return l
}

func (c *Converter) jitdump(path string) (*symtab.FileReader, error) {
	if c.cachedJITDumpKey == path {
		return c.cachedJITDump, c.cachedJITDumpErr
	}

	jitdump, err := c.m.jitdumpCache.JITDumpForPID(c.pid, path)
	c.cachedJITDumpKey = path
	c.cachedJITDump = jitdump
	c.cachedJITDumpErr = err
	return jitdump, err
}

type functionKey struct {
	name     string
	filename string
}

// TODO: add support for startLine of functions.
func (c *Converter) addFunction(
	name string,
	filename string,
) *pprofprofile.Function {
	key := functionKey{name: name, filename: filename}
	if f, ok := c.functionIndex[key]; ok {
		return f
	}

	f := &pprofprofile.Function{
		ID:       uint64(len(c.result.Function) + 1),
		Name:     name,
		Filename: filename,
	}

	c.functionIndex[key] = f
	c.result.Function = append(c.result.Function, f)

	return f
}

func (c *Converter) threadName(proc procfs.Proc, tid int) string {
	if tid == 0 {
		return ""
	}
	threadName, ok := c.threadNameCache[tid]
	if ok {
		return threadName
	}

	tp, err := proc.Thread(tid)
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to get thread info", "pid", c.pid, "tid", tid, "err", err)
		return ""
	}
	threadName, err = tp.Comm()
	if err != nil {
		level.Debug(c.logger).Log("msg", "failed to get thread name", "pid", c.pid, "tid", tid, "err", err)
		return ""
	}

	c.threadNameCache[tid] = threadName
	return threadName
}
