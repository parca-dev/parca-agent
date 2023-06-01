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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/pprof/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/internal/pprof/elfexec"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

const kernelMappingFileName = "[kernel.kallsyms]"

var ErrBaseAddressCannotCalculated = errors.New("base address cannot be calculated")

type AddressOutOfRangeError struct {
	m    *Mapping
	addr uint64
}

func (e *AddressOutOfRangeError) Error() string {
	return fmt.Sprintf("specified address %x is outside the mapping range [%x, %x] for ObjectFile %q", e.addr, e.m.StartAddr, e.m.EndAddr, e.m.fullPath())
}

const (
	lvObtainFD            = "obtain_fd"
	lvOpenObjectfile      = "open_objectfile"
	lvComputeKernelOffset = "compute_kernel_offset"
)

type mapMetrics struct {
	open          *prometheus.CounterVec
	openErrors    *prometheus.CounterVec
	openFDs       prometheus.Gauge
	closeAttempts prometheus.Counter
	closed        *prometheus.CounterVec
	// keptOpenDuration prometheus.Histogram
}

func newMapMetrics(reg prometheus.Registerer) *mapMetrics {
	m := &mapMetrics{
		open: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_mapping_opened_total",
			Help: "Total number of times a mapping was opened.",
		}, []string{"result"}),
		openErrors: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_mapping_open_errors_total",
			Help: "Total number of times a mapping failed to open.",
		}, []string{"type"}),
		openFDs: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "parca_agent_mapping_open_fds",
			Help: "Number of open file descriptors.",
		}),
		closeAttempts: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "parca_agent_mapping_close_attempts_total",
			Help: "Total number of times a mapping was attempted to be closed.",
		}),
		closed: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "parca_agent_mapping_closed_total",
			Help: "Total number of times a mapping was closed.",
		}, []string{"result"}),
	}
	m.open.WithLabelValues(lvSuccess)
	m.open.WithLabelValues(lvFail)
	m.openErrors.WithLabelValues(lvObtainFD)
	m.openErrors.WithLabelValues(lvOpenObjectfile)
	m.openErrors.WithLabelValues(lvComputeKernelOffset)
	m.closed.WithLabelValues(lvSuccess)
	m.closed.WithLabelValues(lvFail)
	return m
}

type MapManager struct {
	*procfs.FS
	metrics *mapMetrics

	objFilePool *objectfile.Pool
}

func NewMapManager(reg prometheus.Registerer, fs procfs.FS, objFilePool *objectfile.Pool) *MapManager {
	return &MapManager{
		&fs,
		newMapMetrics(reg),
		objFilePool,
	}
}

type Mappings []*Mapping

func (ms Mappings) ConvertToPprof() []*profile.Mapping {
	res := make([]*profile.Mapping, 0, len(ms))
	for _, m := range ms {
		res = append(res, m.ConvertToPprof())
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
	idx := 0
	for _, m := range maps {
		mapping, err := mm.newUserMapping(m, pid)
		if err != nil {
			mm.metrics.open.WithLabelValues(lvFail).Inc()
			if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
				// High likely the file was unreachable due to short-lived process.
				// A corresponding metrics should have recorded in newUserMapping.
				continue
			}
			errs = errors.Join(errs, fmt.Errorf("failed to initialize mapping %s: %w", m.Pathname, err))
			continue
		}
		mm.metrics.open.WithLabelValues(lvSuccess).Inc()

		mapping.id = uint64(idx + 1)
		res = append(res, mapping)
		idx++
	}
	return res, errs
}

// MappingForAddr returns the executable mapping that contains the given address.
func (ms Mappings) MappingForAddr(addr uint64) *Mapping {
	for _, m := range ms {
		// Only consider executable mappings.
		if m.IsExecutable() {
			if uint64(m.StartAddr) <= addr && uint64(m.EndAddr) >= addr {
				return m
			}
		}
	}
	return nil
}

func KernelMapping() *Mapping {
	return &Mapping{
		ProcMap: &procfs.ProcMap{
			StartAddr: 0,
			EndAddr:   0,
			Offset:    0,
			Pathname:  kernelMappingFileName,
		},
		pprof: &profile.Mapping{
			File: kernelMappingFileName,
		},
	}
}

type Mapping struct {
	mm *MapManager

	*procfs.ProcMap

	// Offset of kernel relocation symbol.
	// Only defined for kernel images, nil otherwise. e. g. _stext.
	//
	// TODO: Remove or add InitOnce
	kernelOffset *uint64

	// Ensures the base, baseErr are computed once.
	baseOnce *sync.Once
	baseErr  error
	base     uint64
	// Hang on to the object file to prevent GC until base is computed.
	objFile *objectfile.ObjectFile

	// This will be populated if mappping has executable and symbolizable.
	// We intentionally do NOT use an ObjectFile here.
	// So that it could be GCed and closed.
	buildID string

	// Process related fields.
	pid int

	fd int

	uploaded bool

	// pprof related fields.
	id    uint64 // TODO(kakkoyun): Move the ID logic top pprof converter.
	pprof *profile.Mapping
}

// newUserMapping makes sure the mapped file is open and computes the kernel offset.
func (mm *MapManager) newUserMapping(pm *procfs.ProcMap, pid int) (*Mapping, error) {
	m := &Mapping{mm: mm, ProcMap: pm, pid: pid, baseOnce: &sync.Once{}}

	if !m.isSymbolizable() { // No need to open/initialize unsymbolizable mappings.
		return m, nil
	}

	fd, err := syscall.Open(m.fullPath(), syscall.O_RDONLY, 0)
	if err != nil {
		m.close()
		m.mm.metrics.openErrors.WithLabelValues(lvObtainFD).Inc()
		return nil, fmt.Errorf("failed to open mapped file: %w", err)
	}
	m.fd = fd
	m.mm.metrics.openFDs.Inc()

	// TODO(kakkoyun): Handle special mappings. e.g. [vdso]
	obj, err := m.mm.objFilePool.Open(m.fullPath())
	if err != nil {
		m.close()
		m.mm.metrics.openErrors.WithLabelValues(lvOpenObjectfile).Inc()
		return nil, fmt.Errorf("failed to open mapped object file: %w", err)
	}
	defer obj.HoldOn()

	m.objFile = obj // Populated until base is computed.
	m.buildID = obj.BuildID

	if err := m.computeKernelOffset(obj); err != nil {
		m.close()
		m.mm.metrics.openErrors.WithLabelValues(lvComputeKernelOffset).Inc()
		return nil, fmt.Errorf("failed to compute kernel offset: %w", err)
	}
	runtime.SetFinalizer(m, func(m *Mapping) error {
		return m.close()
	})
	return m, nil
}

func (m *Mapping) close() error {
	m.mm.metrics.closeAttempts.Inc()
	if err := syscall.Close(m.fd); err != nil {
		m.mm.metrics.closed.WithLabelValues(lvFail).Inc()
		return fmt.Errorf("failed to close mapped file: %w", err)
	}
	m.mm.metrics.openFDs.Dec()
	m.mm.metrics.closed.WithLabelValues(lvSuccess).Inc()
	return nil
}

// IsExecutable returns true if the mapping is executable.
func (m *Mapping) IsExecutable() bool {
	return m.Perms.Execute
}

// isSymbolizable returns true if the mapping is symbolizable.
func (m *Mapping) isSymbolizable() bool {
	return doesReferToFile(m.Pathname) && m.IsExecutable()
}

func doesReferToFile(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" &&
		!strings.HasPrefix(path, "[") &&
		!strings.HasPrefix(path, "anon_inode:[")
	// NOTICE: Add more patterns when needed.
}

// Root returns the root filesystem of the process that owns the mapping.
func (m *Mapping) Root() string {
	return path.Join("/proc", strconv.Itoa(m.pid), "/root")
}

// fullPath returns path relative to the root namespace of the system.
func (m *Mapping) fullPath() string {
	return path.Join("/proc", strconv.Itoa(m.pid), "/root", m.Pathname)
}

// kernelRelocationSymbol extracts kernel relocation symbol _text or _stext
// for a main linux kernel mapping.
// The mapping file can be [kernel.kallsyms]_text or [kernel.kallsyms]_stext.
func kernelRelocationSymbol(mappingFile string) string {
	const prefix = "[kernel.kallsyms]"
	if !strings.HasPrefix(mappingFile, prefix) {
		return ""
	}
	return mappingFile[len(prefix):]
}

// computeKernelOffset computes the offset of the kernel relocation symbol.
func (m *Mapping) computeKernelOffset(obj *objectfile.ObjectFile) error {
	defer obj.HoldOn()

	if m == nil {
		return nil
	}

	if m.kernelOffset != nil {
		return nil
	}

	var (
		relocationSymbol = kernelRelocationSymbol(m.fullPath())
		kernelOffset     *uint64
		pageAligned      = func(addr uint64) bool { return addr%4096 == 0 }
	)

	if obj == nil {
		panic("object file is nil")
	}

	ef, release, err := obj.ELF()
	if err != nil {
		return fmt.Errorf("failed to get ELF file: %w", err)
	}
	defer release()

	if strings.Contains(m.fullPath(), "vmlinux") ||
		!pageAligned(uint64(m.StartAddr)) || !pageAligned(uint64(m.EndAddr)) || !pageAligned(uint64(m.Offset)) {
		// Reading all Symbols is expensive, and we only rarely need it so
		// we don't want to do it every time. But if _stext happens to be
		// page-aligned but isn't the same as Vaddr, we would symbolize
		// wrong. So if the name the addresses aren't page aligned, or if
		// the name is "vmlinux" we read _stext. We can be wrong if: (1)
		// someone passes a kernel path that doesn't contain "vmlinux" AND
		// (2) _stext is page-aligned AND (3) _stext is not at Vaddr
		symbols, err := ef.Symbols()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return err
		}

		// The kernel relocation symbol (the mapping start address) can be either
		// _text or _stext. When profiles are generated by `perf`, which one was used is
		// distinguished by the mapping name for the kernel image:
		// '[kernel.kallsyms]_text' or '[kernel.kallsyms]_stext', respectively. If we haven't
		// been able to parse it from the mapping, we default to _stext.
		if relocationSymbol == "" {
			relocationSymbol = "_stext"
		}
		for _, s := range symbols {
			sym := s
			if sym.Name == relocationSymbol {
				kernelOffset = &sym.Value
				break
			}
		}
	}

	// Check that we can compute a base for the binary. This may not be the
	// correct base value, so we don't save it. We delay computing the actual base
	// value until we have a sample address for this mapping, so that we can
	// correctly identify the associated program segment that is needed to compute
	// the base.
	if _, err := elfexec.GetBase(
		&ef.FileHeader,
		elfexec.FindTextProgHeader(ef), kernelOffset,
		uint64(m.StartAddr), uint64(m.EndAddr), uint64(m.Offset),
	); err != nil {
		return fmt.Errorf("could not identify base for %s: %w", m.fullPath(), err)
	}
	m.kernelOffset = kernelOffset
	return nil
}

// findProgramHeader returns the program segment that matches the current
// mapping and the given address, or an error if it cannot find a unique program
// header.
func (m *Mapping) findProgramHeader(ef *elf.File, addr uint64) (*elf.ProgHeader, error) {
	// For user space executables, we try to find the actual program segment that
	// is associated with the given mapping. Skip this search if limit <= start.
	// We cannot use just a check on the start address of the mapping to tell if
	// it's a kernel / .ko module mapping, because with quipper address remapping
	// enabled, the address would be in the lower half of the address space.

	if m.kernelOffset != nil || m.StartAddr >= m.EndAddr || uint64(m.EndAddr) >= (uint64(1)<<63) {
		// For the kernel, find the program segment that includes the .text section.
		return elfexec.FindTextProgHeader(ef), nil
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
		//nolint:nilnil
		return nil, nil
	}
	// Get all program headers associated with the mapping.
	headers := elfexec.ProgramHeadersForMapping(phdrs, uint64(m.Offset), uint64(m.EndAddr)-uint64(m.StartAddr))
	if len(headers) == 0 {
		return nil, errors.New("no program header matches mapping info")
	}
	if len(headers) == 1 {
		return headers[0], nil
	}

	// Use the file offset corresponding to the address to symbolize, to narrow
	// down the header.
	return elfexec.HeaderForFileOffset(headers, addr-uint64(m.StartAddr)+uint64(m.Offset))
}

// Normalize converts the given address to the address relative to the start of the
// object file.
func (m *Mapping) Normalize(addr uint64) (uint64, error) {
	if addr < uint64(m.StartAddr) || addr >= uint64(m.EndAddr) {
		return 0, &AddressOutOfRangeError{m, addr}
	}
	m.baseOnce.Do(func() { m.computeBase(addr) })
	if m.baseErr != nil {
		return 0, errors.Join(m.baseErr, ErrBaseAddressCannotCalculated)
	}
	return addr - m.base, nil
}

// computeBase computes the relocation base for the given binary ObjectFile only if
// the mapping field is set. It populates the base fields returns an error.
func (m *Mapping) computeBase(addr uint64) {
	ef, release, err := m.objFile.ELF()
	if err != nil {
		m.baseErr = fmt.Errorf("failed to create ELF file for ObjectFile %q: %w", m.objFile.Path, err)
		return
	}
	defer release()

	ph, err := m.findProgramHeader(ef, addr)
	if err != nil {
		m.baseErr = fmt.Errorf("failed to find program header for ObjectFile %q, ELF mapping %#v, address %x: %w", m.objFile.Path, m, addr, err)
		return
	}

	base, err := elfexec.GetBase(
		&ef.FileHeader, ph, m.kernelOffset,
		uint64(m.StartAddr), uint64(m.EndAddr), uint64(m.Offset),
	)
	if err != nil {
		m.baseErr = fmt.Errorf("failed to get base for ObjectFile %q, ELF mapping %#v, address %x: %w", m.objFile.Path, m, addr, err)
		return
	}
	m.base = base
	m.objFile = nil
}

// ConvertToPprof converts the Mapping to a pprof profile.Mapping.
func (m *Mapping) ConvertToPprof() *profile.Mapping {
	var (
		buildID = m.buildID
		path    = m.Pathname
	)

	if buildID == "" {
		buildID = "unknown"
	}
	if path == "" {
		// TODO: Maybe add detection for JITs that use files.
		path = "jit"
	}

	if m.pprof != nil {
		return m.pprof
	}

	m.pprof = &profile.Mapping{
		ID:      m.id,
		Start:   uint64(m.StartAddr),
		Limit:   uint64(m.EndAddr),
		Offset:  uint64(m.Offset),
		BuildID: buildID,
		File:    path,
	}
	return m.pprof
}
