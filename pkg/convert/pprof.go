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

package convert

import (
	"fmt"
	"time"

	"github.com/google/pprof/profile"

	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

// TODO(kakkoyun): We can use a pool of pprof here.

type ProfileToPprofConverter struct {
	mappingCache map[string]*profile.Mapping
}

func NewProfileToPprofConverter() *ProfileToPprofConverter {
	return &ProfileToPprofConverter{
		mappingCache: map[string]*profile.Mapping{},
	}
}

// Convert converts several per process Profile to a pprof Profile.
func (c *ProfileToPprofConverter) Convert(captureTime time.Time, periodNS int64, prs ...*profiler.Profile) (*profile.Profile, error) {
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{{
			Type: "samples",
			Unit: "count",
		}},
		TimeNanos:     captureTime.UnixNano(),
		DurationNanos: int64(time.Since(captureTime)),

		// Sampling at 100Hz would be every 10 Million nanoseconds.
		PeriodType: &profile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		Period: periodNS,
	}
	if len(prs) == 0 {
		return prof, nil
	}

	// Build Profile from samples, locations and mappings.
	for _, pr := range prs {
		for _, s := range pr.Samples {
			prof.Sample = append(prof.Sample, s.Sample)
		}
	}

	// Locations.
	for _, pr := range prs {
		for i, l := range pr.Locations {
			l.ID = uint64(i) + 1
			l.Location.Mapping = c.mappingToPprof(l.Mapping)
			prof.Location = append(prof.Location, l.Location)
		}
	}

	// User mappings.
	for _, pr := range prs {
		for i, m := range c.mappingsToPprof(pr.UserMappings) {
			m.ID = uint64(i) + 1
			prof.Mapping = append(prof.Mapping, m)
		}
	}

	// Kernel mappings.
	lastProfile := prs[len(prs)-1]
	kernelMapping := c.mappingToPprof(lastProfile.KernelMapping)
	kernelMapping.ID = uint64(len(prof.Mapping)) + 1
	prof.Mapping = append(prof.Mapping, kernelMapping)

	// Symbolized functions.
	for _, pr := range prs {
		for i, f := range pr.Functions {
			f.ID = uint64(i) + 1
			prof.Function = append(prof.Function, f.Function)
		}
	}

	if err := prof.CheckValid(); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}
	return prof, nil
}

// mappingToPprof converts the Mapping to a pprof profile.Mapping.
func (c *ProfileToPprofConverter) mappingToPprof(m *process.Mapping) *profile.Mapping {
	buildID := m.BuildID
	if buildID == "" {
		buildID = "unknown"
	}

	path := "jit" // TODO: Maybe add detection for JITs that use files.
	if p := m.Pathname; p != "" {
		path = p
	}

	key := fmt.Sprintf("%s/%s/%d/%d", path, buildID, m.StartAddr, m.EndAddr)
	if m, ok := c.mappingCache[key]; ok {
		return m
	}

	mp := &profile.Mapping{
		Start:   uint64(m.StartAddr),
		Limit:   uint64(m.EndAddr),
		Offset:  uint64(m.Offset),
		BuildID: buildID,
		File:    path,
	}
	c.mappingCache[key] = mp
	return mp
}

// mappingsToPprof converts the Mappings to a list of pprof profile.Mappings.
func (c *ProfileToPprofConverter) mappingsToPprof(ms process.Mappings) []*profile.Mapping {
	res := make([]*profile.Mapping, 0, len(ms))
	for _, m := range ms {
		res = append(res, c.mappingToPprof(m))
	}
	return res
}
