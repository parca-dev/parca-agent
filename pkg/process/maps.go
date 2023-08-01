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

package process

import (
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/google/pprof/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/elfreader"
	"github.com/parca-dev/parca-agent/pkg/kernel"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type normalizationMetrics struct {
	baseCalculationInitSuccess      prometheus.Counter
	baseCalculationInitError        prometheus.Counter
	baseCalculationNormalizeSuccess prometheus.Counter
	baseCalculationNormalizeError   prometheus.Counter
}

func newNormalizationMetrics(reg prometheus.Registerer) *normalizationMetrics {
	baseCalculation := promauto.With(reg).NewCounterVec(
		prometheus.CounterOpts{
			Name: "parca_agent_base_calculation_total",
			Help: "Total number of base calculation attempts by stage.",
		},
		[]string{"stage", "result"},
	)
	m := &normalizationMetrics{
		baseCalculationInitSuccess:      baseCalculation.WithLabelValues("init", "success"),
		baseCalculationInitError:        baseCalculation.WithLabelValues("init", "error"),
		baseCalculationNormalizeSuccess: baseCalculation.WithLabelValues("normalize", "success"),
		baseCalculationNormalizeError:   baseCalculation.WithLabelValues("normalize", "error"),
	}
	return m
}

type MapManager struct {
	procfs.FS

	// normalizationEnabled indicates whether the profiler has to
	// normalize sampled addresses for PIC/PIE (position independent code/executable).
	normalizationEnabled bool
	normalizationMetrics *normalizationMetrics

	objFilePool *objectfile.Pool
}

func NewMapManager(
	reg prometheus.Registerer,
	fs procfs.FS,
	objFilePool *objectfile.Pool,
	normalizationEnabled bool,
) *MapManager {
	return &MapManager{
		FS:                   fs,
		objFilePool:          objFilePool,
		normalizationEnabled: normalizationEnabled,
		normalizationMetrics: newNormalizationMetrics(reg),
	}
}

type Mappings []*Mapping

func (ms Mappings) ConvertToPprof() []*profile.Mapping {
	res := make([]*profile.Mapping, 0, len(ms))

	// pprof IDs start at 1 to be able to distinguish them from 0 (default
	// value aka unset).
	i := uint64(1)
	for _, m := range ms {
		pprofMapping := m.convertToPprof()
		pprofMapping.ID = i
		res = append(res, pprofMapping)
		i++
	}
	return res
}

func (ms Mappings) ExecutableSections() []*Mapping {
	res := make([]*Mapping, 0, len(ms))

	for _, m := range ms {
		if m.isExecutable() {
			res = append(res, m)
		}
	}

	return res
}

var (
	ErrProcessMapNotFound = errors.New("perf-map not found")
	ErrProcNotFound       = errors.New("process not found")
)

// MappingsForPID returns all the mappings for the given PID.
func (mm *MapManager) MappingsForPID(pid int) (Mappings, error) {
	proc, err := mm.Proc(pid)
	if err != nil {
		return nil, errors.Join(ErrProcNotFound, fmt.Errorf("failed to open proc %d: %w", pid, err))
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, errors.Join(ErrProcNotFound, fmt.Errorf("failed to read proc maps for proc %d: %w", pid, err))
	}

	res := make([]*Mapping, 0, len(maps))
	var errs error
	for _, m := range maps {
		mapping, err := mm.newUserMapping(m, pid)
		if err != nil {
			var elfErr *elf.FormatError
			if errors.As(err, &elfErr) {
				// We don't want to count these as errors. This just means the file
				// is not an ELF file.
				continue
			}
			errs = errors.Join(errs, fmt.Errorf("failed to initialize mapping %s: %w", m.Pathname, err))
			if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
				// High likely the file was unreachable due to short-lived process.
				break
			}
		}
		res = append(res, mapping)
	}
	// Any errors that are returned prevent agent to cache the process info.
	return res, errs
}

// MappingForAddr returns the executable mapping that contains the given address.
func (ms Mappings) MappingForAddr(addr uint64) *Mapping {
	for _, m := range ms {
		// Only consider executable mappings.
		if m.isExecutable() {
			if uint64(m.StartAddr) <= addr && uint64(m.EndAddr) >= addr {
				return m
			}
		}
	}
	return nil
}

type Mapping struct {
	mm *MapManager

	*procfs.ProcMap

	// Process related fields.
	PID int

	// This will be populated if mappping has executable and symbolizable.
	// We intentionally do NOT use an ObjectFile here.
	// So that it could be GCed and closed.
	// This is needed for pprof conversion.
	BuildID string

	base     uint64
	baseOnce *sync.Once
	baseSet  bool
	baseErr  error

	IsJitDump bool

	// This mapping had no path associated with it. Usually this means the
	// mapping is a JIT compiled section.
	NoFileMapping bool

	containsDebuginfoToUpload bool
}

// newUserMapping makes sure the mapped file is open and computes the kernel offset.
func (mm *MapManager) newUserMapping(pm *procfs.ProcMap, pid int) (*Mapping, error) {
	m := &Mapping{
		mm:      mm,
		ProcMap: pm,
		PID:     pid,

		baseOnce:                  &sync.Once{},
		containsDebuginfoToUpload: true,
	}

	if !m.isSymbolizable() { // No need to open/initialize unsymbolizable mappings.
		if m.Pathname == "" {
			m.NoFileMapping = true
		}
		m.containsDebuginfoToUpload = false
		return m, nil
	}

	obj, err := m.mm.objFilePool.Open(m.AbsolutePath())
	if err != nil {
		var elfErr *elf.FormatError
		// This magic number is the magic number for JITDump files.
		if errors.As(err, &elfErr) && elfErr.Error() == "bad magic number '[68 84 105 74]' in record at byte 0x0" {
			m.containsDebuginfoToUpload = false
			m.IsJitDump = true

			return m, nil
		}
		return nil, fmt.Errorf("failed to open mapped object file: %w", err)
	}

	ef, release, err := obj.ELF()
	if err != nil {
		return nil, fmt.Errorf("failed to get ELF file: %w", err)
	}
	defer release()

	m.BuildID = obj.BuildID

	// Check that we can compute a base for the binary. This may not be the
	// correct base value, so we don't save it. We delay computing the actual base
	// value until we have a sample address for this mapping, so that we can
	// correctly identify the associated program segment that is needed to compute
	// the base.
	base, err := m.computeBaseWithoutAddr(ef)
	if err == nil {
		// If we can compute the base without addr, we can use it as the base.
		m.base = base
		m.mm.normalizationMetrics.baseCalculationInitSuccess.Inc()
	} else {
		m.mm.normalizationMetrics.baseCalculationInitError.Inc()
	}

	return m, nil
}

// isExecutable returns true if the mapping is executable.
func (m *Mapping) isExecutable() bool {
	return m.Perms.Execute
}

// isSymbolizable returns true if the mapping is symbolizable.
func (m *Mapping) isSymbolizable() bool {
	return doesReferToFile(m.Pathname) && m.isExecutable()
}

func doesReferToFile(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" &&
		path != "jit" &&
		!strings.HasPrefix(path, "[") &&
		!strings.HasPrefix(path, "anon_inode:[") &&
		!strings.Contains(path, "(deleted)") &&
		!strings.Contains(path, "memfd:")
	// NOTICE: Add more patterns when needed.
}

// Root returns the root filesystem of the process that owns the mapping.
func (m *Mapping) Root() string {
	return path.Join("/proc", strconv.Itoa(m.PID), "/root")
}

// AbsolutePath returns path relative to the root namespace of the system.
func (m *Mapping) AbsolutePath() string {
	return path.Join("/proc", strconv.Itoa(m.PID), "/root", m.Pathname)
}

// findProgramHeader returns the program segment that matches the current
// mapping and the given address, or an error if it cannot find a unique program
// header.
func (m *Mapping) findProgramHeader(ef *elf.File, addr uint64) (*elf.ProgHeader, error) {
	// For user space executables, we try to find the actual program segment that
	// is associated with the given mapping. Skip this search if limit <= start.
	if m.StartAddr >= m.EndAddr || uint64(m.EndAddr) >= (uint64(1)<<63) {
		return elfreader.FindTextProgHeader(ef), nil
	}

	// Fetch all the loadable segments.
	var phdrs []elf.ProgHeader
	for i := range ef.Progs {
		if ef.Progs[i].Type == elf.PT_LOAD {
			phdrs = append(phdrs, ef.Progs[i].ProgHeader)
		}
	}
	// Some ELF files don't contain any loadable program segments, e.g. .ko
	// kernel modules. It's not an error to have no header in such cases.
	if len(phdrs) == 0 {
		return nil, nil //nolint:nilnil
	}
	// Get all program headers associated with the mapping.
	headers := elfreader.ProgramHeadersForMapping(phdrs, uint64(m.Offset), uint64(m.EndAddr)-uint64(m.StartAddr))
	if len(headers) == 0 {
		return nil, errors.New("no program header matches mapping info")
	}
	if len(headers) == 1 {
		return headers[0], nil
	}

	// Use the file offset corresponding to the address to symbolize, to narrow
	// down the header.
	return elfreader.HeaderForFileOffset(headers, addr-uint64(m.StartAddr)+uint64(m.Offset))
}

func (m *Mapping) computeBase(ef *elf.File, addr uint64) (uint64, error) {
	if m == nil {
		return 0, nil
	}
	if addr < uint64(m.StartAddr) || addr >= uint64(m.EndAddr) {
		return 0, fmt.Errorf("specified address %x is outside the mapping range [%x, %x]", addr, m.StartAddr, m.EndAddr)
	}

	loadSegment, err := m.findProgramHeader(ef, addr)
	if err != nil {
		return 0, fmt.Errorf("failed to find program header for mapping %#v: %w", m, err)
	}

	base, err := elfreader.Base(
		&ef.FileHeader, loadSegment,
		uint64(m.StartAddr),
		uint64(m.EndAddr),
		uint64(m.Offset),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get base from ELF mapping %#v: %w", m, err)
	}
	return base, nil
}

func (m *Mapping) computeBaseWithoutAddr(ef *elf.File) (uint64, error) {
	loadSegment := elfreader.FindTextProgHeader(ef)
	base, err := elfreader.Base(
		&ef.FileHeader, loadSegment,
		uint64(m.StartAddr),
		uint64(m.EndAddr),
		uint64(m.Offset),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get base from ELF mapping %#v: %w", m, err)
	}
	return base, nil
}

// Normalize converts the given address to the address relative to the start of the
// object file.
func (m *Mapping) Normalize(addr uint64) (uint64, error) {
	if !m.mm.normalizationEnabled {
		return addr, nil
	}

	// Fast path: if the base is already set, we can just subtract it from the address.
	if m.baseSet {
		return addr - m.base, nil
	}

	// Slow path: we need to compute the base using the received address to find the program header.
	if m.baseErr == nil {
		m.baseOnce.Do(func() {
			defer func() {
				m.baseSet = true

				if m.baseErr != nil {
					m.mm.normalizationMetrics.baseCalculationNormalizeError.Inc()
				}
			}()

			path := m.AbsolutePath()
			if m.Pathname == "[vdso]" {
				// vdso is a special case.
				// On some systems, the vdso is mapped to a global file shared by all processes.
				var err error
				path, err = kernel.FindVDSO()
				if err != nil {
					m.baseErr = fmt.Errorf("failed to find vdso file: %w", err)
					return
				}
			}

			obj, err := m.mm.objFilePool.Open(path)
			if err != nil {
				m.baseErr = fmt.Errorf("failed to open mapped object file: %w", err)
				return
			}

			ef, release, err := obj.ELF()
			if err != nil {
				m.baseErr = fmt.Errorf("failed to get ELF file: %w", err)
				return
			}
			defer release()

			base, err := m.computeBase(ef, addr)
			if err != nil {
				m.baseErr = fmt.Errorf("failed to compute base: %w", err)
				return
			}

			m.base = base
			m.mm.normalizationMetrics.baseCalculationNormalizeSuccess.Inc()
		})
		if m.baseErr != nil {
			return 0, fmt.Errorf("failed to compute base: %w", m.baseErr)
		}
	}

	// If base address not set previously, it might be set now.
	if m.baseSet {
		return addr - m.base, nil
	}

	// Failed to compute base address. Leave the address as is.
	return addr, nil
}

// convertToPprof converts the Mapping to a pprof profile.Mapping.
func (m *Mapping) convertToPprof() *profile.Mapping {
	var (
		buildID = m.BuildID
		path    = m.Pathname
	)

	if buildID == "" {
		buildID = "unknown"
	}
	if path == "" {
		// TODO: Maybe add detection for JITs that use files.
		path = "jit"
	}

	return &profile.Mapping{
		Start:   uint64(m.StartAddr),
		Limit:   uint64(m.EndAddr),
		Offset:  uint64(m.Offset),
		BuildID: buildID,
		File:    path,
	}
}
