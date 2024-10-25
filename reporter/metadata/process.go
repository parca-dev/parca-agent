package metadata

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"github.com/prometheus/prometheus/model/labels"
	log "github.com/sirupsen/logrus"
)

var ErrFileParse = errors.New("Error Parsing File")

// ExecInfo enriches an executable with additional metadata.
type ExecInfo struct {
	FileName string
	BuildID  string
	Compiler string
	Static   bool
	Stripped bool
}

// cgroup models one line from /proc/[pid]/cgroup. Each cgroup struct describes the placement of a PID inside a
// specific control hierarchy. The kernel has two cgroup APIs, v1 and v2. v1 has one hierarchy per available resource
// controller, while v2 has one unified hierarchy shared by all controllers. Regardless of v1 or v2, all hierarchies
// contain all running processes, so the question answerable with a cgroup struct is 'where is this process in
// this hierarchy' (where==what path on the specific cgroupfs). By prefixing this path with the mount point of
// *this specific* hierarchy, you can locate the relevant pseudo-files needed to read/set the data for this PID
// in this hierarchy
//
// Also see http://man7.org/linux/man-pages/man7/cgroups.7.html
type cgroup struct {
	// HierarchyID that can be matched to a named hierarchy using /proc/cgroups. Cgroups V2 only has one
	// hierarchy, so HierarchyID is always 0. For cgroups v1 this is a unique ID number
	hierarchyID int
	// Controllers using this hierarchy of processes. Controllers are also known as subsystems. For
	// Cgroups V2 this may be empty, as all active controllers use the same hierarchy
	controllers []string
	// Path of this control group, relative to the mount point of the cgroupfs representing this specific
	// hierarchy
	path string
}

// parseCgroupString parses each line of the /proc/[pid]/cgroup file
// Line format is hierarchyID:[controller1,controller2]:path.
func parseCgroupString(cgroupStr string) (*cgroup, error) {
	var err error

	fields := strings.SplitN(cgroupStr, ":", 3)
	if len(fields) < 3 {
		return nil, fmt.Errorf("%w: 3+ fields required, found %d fields in cgroup string: %s", ErrFileParse, len(fields), cgroupStr)
	}

	cgroup := &cgroup{
		path:        fields[2],
		controllers: nil,
	}
	cgroup.hierarchyID, err = strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%w: hierarchy ID: %q", ErrFileParse, cgroup.hierarchyID)
	}
	if fields[1] != "" {
		ssNames := strings.Split(fields[1], ",")
		cgroup.controllers = append(cgroup.controllers, ssNames...)
	}
	return cgroup, nil
}

// parseCgroups reads each line of the /proc/[pid]/cgroup file.
func parseCgroups(data []byte) ([]cgroup, error) {
	var cgroups []cgroup
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		mountString := scanner.Text()
		parsedMounts, err := parseCgroupString(mountString)
		if err != nil {
			return nil, err
		}
		cgroups = append(cgroups, *parsedMounts)
	}

	err := scanner.Err()
	return cgroups, err
}

// readFileNoStat uses io.ReadAll to read contents of entire file.
// This is similar to os.ReadFile but without the call to os.Stat, because
// many files in /proc and /sys report incorrect file sizes (either 0 or 4096).
// Reads a max file size of 1024kB.  For files larger than this, a scanner
// should be used.
func readFileNoStat(filename string) ([]byte, error) {
	const maxBufferSize = 1024 * 1024

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := io.LimitReader(f, maxBufferSize)
	return io.ReadAll(reader)
}

// findContainerGroup returns the cgroup with the cpu controller or first systemd slice cgroup.
func findContainerGroup(cgroups []cgroup) cgroup {
	// If only 1 cgroup, simply return it
	if len(cgroups) == 1 {
		return cgroups[0]
	}

	for _, cg := range cgroups {
		// Find first cgroup v1 with cpu controller
		for _, ctlr := range cg.controllers {
			if ctlr == "cpu" {
				return cg
			}
		}

		// Find first systemd slice
		// https://systemd.io/CGROUP_DELEGATION/#systemds-unit-types
		if strings.HasPrefix(cg.path, "/system.slice/") || strings.HasPrefix(cg.path, "/user.slice/") {
			return cg
		}

		// FIXME: what are we looking for here?
		// https://systemd.io/CGROUP_DELEGATION/#controller-support
		for _, ctlr := range cg.controllers {
			if strings.Contains(ctlr, "systemd") {
				return cg
			}
		}
	}

	return cgroup{}
}

type process int32

func (p process) path(path string) string {
	return filepath.Join("/proc", strconv.Itoa(int(p)), path)
}

func (p process) readMainExecutableFileID() (libpf.FileID, error) {
	return libpf.FileIDFromExecutableFile(p.path("exe"))
}

type mainExecutableMetadataProvider struct {
	executableCache *lru.SyncedLRU[libpf.FileID, ExecInfo]
}

// NewMainExecutableMetadataProvider creates a new mainExecutableMetadataProvider.
func NewMainExecutableMetadataProvider(
	executableCache *lru.SyncedLRU[libpf.FileID, ExecInfo],
) MetadataProvider {
	return &mainExecutableMetadataProvider{
		executableCache: executableCache,
	}
}

// AddMetadata adds metadata labels for the main executable of a process to the given labels.Builder.
func (p *mainExecutableMetadataProvider) AddMetadata(
	pid libpf.PID,
	lb *labels.Builder,
) bool {
	cacheable := true

	fileID, err := process(pid).readMainExecutableFileID()
	if err != nil {
		log.Debugf("Failed to get fileID for PID %d: %v", pid, err)
		cacheable = false
	}
	lb.Set("__meta_process_executable_file_id", fileID.StringNoQuotes())

	mainExecInfo, exists := p.executableCache.Get(fileID)
	if !exists {
		log.Debugf("Failed to get main executable metadata for PID %d, continuing but metadata might be incomplete", pid)
		cacheable = false
	}

	lb.Set("__meta_process_executable_name", mainExecInfo.FileName)
	lb.Set("__meta_process_executable_build_id", mainExecInfo.BuildID)
	lb.Set("__meta_process_executable_compiler", mainExecInfo.Compiler)
	lb.Set("__meta_process_executable_static", strconv.FormatBool(mainExecInfo.Static))
	lb.Set("__meta_process_executable_stripped", strconv.FormatBool(mainExecInfo.Stripped))

	return cacheable
}

type processMetadataProvider struct{}

// NewProcessMetadataProvider creates a new processMetadataProvider.
func NewProcessMetadataProvider() MetadataProvider {
	return &processMetadataProvider{}
}

// AddMetadata adds metadata labels for a process to the given labels.Builder.
func (pmp *processMetadataProvider) AddMetadata(pid libpf.PID, lb *labels.Builder) bool {
	cache := true
	lb.Set("__meta_process_pid", strconv.Itoa(int(pid)))

	p := process(pid)

	cmdline, err := p.cmdline()
	if err != nil {
		log.Debugf("Failed to get cmdline for PID %d: %v", pid, err)
		cache = false
	} else {
		lb.Set("__meta_process_cmdline", strings.Join(cmdline, " "))
	}

	comm, err := p.comm()
	if err != nil {
		log.Debugf("Failed to get comm for PID %d: %v", pid, err)
		cache = false
	} else {
		lb.Set("comm", comm)
	}

	cgroup, err := p.cgroup()
	if err != nil {
		log.Debugf("Failed to get cgroups for PID %d: %v", pid, err)
		cache = false
	} else {
		lb.Set("__meta_process_cgroup", cgroup.path)
	}

	stat, err := p.stat()
	if err != nil {
		log.Debugf("Failed to get stat for PID %d: %v", pid, err)
		cache = false
	} else {
		lb.Set("__meta_process_ppid", strconv.Itoa(stat.PPID))
	}

	return cache
}

// cgroup reads from /proc/<pid>/cgroups and returns a []*cgroup struct locating this PID in each process
// control hierarchy running on this system. On every system (v1 and v2), all hierarchies contain all processes,
// so the len of the returned struct is equal to the number of active hierarchies on this system.
func (p process) cgroup() (cgroup, error) {
	data, err := readFileNoStat(p.path("cgroup"))
	if err != nil {
		return cgroup{}, err
	}
	cgroups, err := parseCgroups(data)
	if err != nil {
		return cgroup{}, err
	}

	return findContainerGroup(cgroups), nil
}

// cmdline reads from /proc/<pid>/cmdline and returns the command line arguments of this process.
func (p process) cmdline() ([]string, error) {
	data, err := readFileNoStat(p.path("cmdline"))
	if err != nil {
		return nil, err
	}

	if len(data) < 1 {
		return []string{}, nil
	}

	return strings.Split(string(bytes.TrimRight(data, "\x00")), "\x00"), nil
}

// Comm reads from /proc/<pid>/comm and returns the command name of this process.
func (p process) comm() (string, error) {
	data, err := readFileNoStat(p.path("comm"))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// procStat provides status information about the process,
// read from /proc/[pid]/stat.
type procStat struct {
	// The process ID.
	PID int
	// The filename of the executable.
	Comm string
	// The process state.
	State string
	// The PID of the parent of this process.
	PPID int
	// The process group ID of the process.
	PGRP int
	// The session ID of the process.
	Session int
	// The controlling terminal of the process.
	TTY int
	// The ID of the foreground process group of the controlling terminal of
	// the process.
	TPGID int
	// The kernel flags word of the process.
	Flags uint
	// The number of minor faults the process has made which have not required
	// loading a memory page from disk.
	MinFlt uint
	// The number of minor faults that the process's waited-for children have
	// made.
	CMinFlt uint
	// The number of major faults the process has made which have required
	// loading a memory page from disk.
	MajFlt uint
	// The number of major faults that the process's waited-for children have
	// made.
	CMajFlt uint
	// Amount of time that this process has been scheduled in user mode,
	// measured in clock ticks.
	UTime uint
	// Amount of time that this process has been scheduled in kernel mode,
	// measured in clock ticks.
	STime uint
	// Amount of time that this process's waited-for children have been
	// scheduled in user mode, measured in clock ticks.
	CUTime int
	// Amount of time that this process's waited-for children have been
	// scheduled in kernel mode, measured in clock ticks.
	CSTime int
	// For processes running a real-time scheduling policy, this is the negated
	// scheduling priority, minus one.
	Priority int
	// The nice value, a value in the range 19 (low priority) to -20 (high
	// priority).
	Nice int
	// Number of threads in this process.
	NumThreads int
	// The time the process started after system boot, the value is expressed
	// in clock ticks.
	Starttime uint64
	// Virtual memory size in bytes.
	VSize uint
	// Resident set size in pages.
	RSS int
	// Soft limit in bytes on the rss of the process.
	RSSLimit uint64
	// CPU number last executed on.
	Processor uint
	// Real-time scheduling priority, a number in the range 1 to 99 for processes
	// scheduled under a real-time policy, or 0, for non-real-time processes.
	RTPriority uint
	// Scheduling policy.
	Policy uint
	// Aggregated block I/O delays, measured in clock ticks (centiseconds).
	DelayAcctBlkIOTicks uint64
	// Guest time of the process (time spent running a virtual CPU for a guest
	// operating system), measured in clock ticks.
	GuestTime int
	// Guest time of the process's children, measured in clock ticks.
	CGuestTime int
}

// Stat returns the current status information of the process.
func (p process) stat() (procStat, error) {
	data, err := readFileNoStat(p.path("stat"))
	if err != nil {
		return procStat{}, err
	}

	var (
		ignoreInt64  int64
		ignoreUint64 uint64

		s = procStat{PID: int(p)}
		l = bytes.Index(data, []byte("("))
		r = bytes.LastIndex(data, []byte(")"))
	)

	if l < 0 || r < 0 {
		return procStat{}, fmt.Errorf("%w: unexpected format, couldn't extract comm %q", ErrFileParse, data)
	}

	s.Comm = string(data[l+1 : r])

	// Check the following resources for the details about the particular stat
	// fields and their data types:
	// * https://man7.org/linux/man-pages/man5/proc.5.html
	// * https://man7.org/linux/man-pages/man3/scanf.3.html
	_, err = fmt.Fscan(
		bytes.NewBuffer(data[r+2:]),
		&s.State,
		&s.PPID,
		&s.PGRP,
		&s.Session,
		&s.TTY,
		&s.TPGID,
		&s.Flags,
		&s.MinFlt,
		&s.CMinFlt,
		&s.MajFlt,
		&s.CMajFlt,
		&s.UTime,
		&s.STime,
		&s.CUTime,
		&s.CSTime,
		&s.Priority,
		&s.Nice,
		&s.NumThreads,
		&ignoreInt64,
		&s.Starttime,
		&s.VSize,
		&s.RSS,
		&s.RSSLimit,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreUint64,
		&ignoreInt64,
		&s.Processor,
		&s.RTPriority,
		&s.Policy,
		&s.DelayAcctBlkIOTicks,
		&s.GuestTime,
		&s.CGuestTime,
	)
	if err != nil {
		return procStat{}, err
	}

	return s, nil
}
