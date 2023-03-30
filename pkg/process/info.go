package process

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/goburrow/cache"
	burrow "github.com/goburrow/cache"
	"github.com/hashicorp/go-multierror"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"
)

type metrics struct{}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{}
	return m
}

type InfoManager struct {
	metrics *metrics

	logger log.Logger
	cache  burrow.Cache
	sfg    singleflight.Group

	mapManager       *MapManager
	debuginfoManager *debuginfo.Manager
}

func onRemoval(_ burrow.Key, b burrow.Value) {
	info, ok := b.(Info)
	if !ok {
		panic("received the wrong type in the info cache")
	}

	for _, mapping := range info.Mappings {
		mapping.objFile.ObjectFile.File.Close()
	}
}

func NewInfoManager(logger log.Logger, reg prometheus.Registerer, mm *MapManager, dim *debuginfo.Manager, profilingDuration time.Duration) *InfoManager {
	return &InfoManager{
		logger:  logger,
		metrics: newMetrics(reg),
		cache: burrow.New(
			cache.WithMaximumSize(5000),
			// @nocommit: Add jitter so we don't have to recompute the information
			// at the same time for many processes if many are evicted.
			cache.WithExpireAfterAccess(10*profilingDuration), // Just to be sure.
			cache.WithRemovalListener(onRemoval),
			// TODO(kkakoyun): Write a burrow.Cache statsCounter collector.
		),
		mapManager:       mm,
		debuginfoManager: dim,
		sfg:              singleflight.Group{},
	}
}

type Info struct {
	// TODO(kakkoyun): Put all the following fields in a struct.
	// - PerfMaps
	// - Unwind Information
	Mappings Mappings
}

// obtainRequiredInfoForProcess collects the required information for a process.
func (im *InfoManager) ObtainRequiredInfoForProcess(ctx context.Context, pid int) error {
	// Cache will keep the value as long as the process is sends to the event channel.
	// See the cache initialization for the eviction policy and the eviction TTL.
	_, exists := im.cache.GetIfPresent(pid)
	if exists {
		return nil
	}

	/*

		event of new process:
			-> getinfo
				-> is getting a bunch of things, including mappings
					-> for each mapping, extract or find debuginfo (on success, add data to channel)


		goroutine:
			reads from channel
			tries to upload
				on failure in re-enqueues
					- what happens if we always fail? -> we can keep the current retry co
	*/
	_, err, _ := im.sfg.Do(strconv.Itoa(pid), func() (interface{}, error) {
		mappings, err := im.mapManager.MappingsForPID(pid)
		if err != nil {
			return nil, err
		}

		var (
			errors *multierror.Error

			processInfo = Info{
				Mappings: mappings,
			}
		)
		for _, m := range processInfo.Mappings {
			objFile, err := mappedObjectFile(pid, m)
			if err != nil {
				errors = multierror.Append(errors, err)
				continue
			}
			m.objFile = objFile
			m.Pprof = convertToPpprof(m)
		}

		// Upload debug information of the discovered object files.
		if im.debuginfoManager != nil {
			// TODO: We need a retry mechanism here.
			objectFiles := make([]*objectfile.MappedObjectFile, 0, len(processInfo.Mappings))
			for _, mapping := range processInfo.Mappings {
				objectFiles = append(objectFiles, mapping.objFile)
			}
			im.debuginfoManager.EnsureUploaded(ctx, objectFiles)
		}

		im.cache.Put(pid, processInfo)
		return nil, errors.ErrorOrNil()
	})

	return err
}

func (im *InfoManager) InfoForPID(pid int) *Info {
	v, ok := im.cache.GetIfPresent(pid)
	if !ok {
		return nil
	}

	info, ok := v.(Info)
	if !ok {
		panic("received the wrong type in the info cache")
	}

	return &info
}

// mappedObjectFile opens the specified executable or library file from the process.
func mappedObjectFile(pid int, m *Mapping) (*objectfile.MappedObjectFile, error) {
	if m.Pathname == "" {
		return nil, errors.New("not found")
	}

	// TODO: This could be incorrect. Check the new Pathname.
	filePath := path.Join("/proc", strconv.FormatInt(int64(pid), 10), "/root", m.Pathname)
	objFile, err := objectfile.Open(filePath, uint64(m.StartAddr), uint64(m.EndAddr), uint64(m.Offset))
	if err != nil {
		return nil, fmt.Errorf("failed to open mapped file: %w", err)
	}
	// @nocommit: Here m.File doesn't have the pid namespace component to it. Check this
	// (filePath has it).
	return &objectfile.MappedObjectFile{ObjectFile: objFile, PID: pid, File: m.Pathname}, nil
}

func (i *Info) Normalize(addr uint64) (uint64, error) {
	m := i.Mappings.MappingForAddr(addr)
	if m == nil {
		return 0, errors.New("mapping is nil")
	}

	objFile := m.objFile
	if objFile == nil {
		return 0, errors.New("objFile is nil")
	}

	// Transform the address using calculated base address for the binary.
	normalizedAddr, err := objFile.ObjAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to get normalized address from object file: %w", err)
	}

	return normalizedAddr, nil
}
