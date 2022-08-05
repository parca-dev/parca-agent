// Copyright (c) 2022 The Parca Authors
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

package profiler

import (
	"time"

	"github.com/google/pprof/profile"
)

// ConvertToPprof converts several per process Profile to a pprof Profile.
func ConvertToPprof(captureTime time.Time, prs ...*Profile) (*profile.Profile, error) {
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{{
			Type: "samples",
			Unit: "count",
		}},
		TimeNanos:     captureTime.UnixNano(),
		DurationNanos: int64(time.Since(captureTime)),

		// We sample at 100Hz, which is every 10 Million nanoseconds.
		PeriodType: &profile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		Period: 10000000,
	}
	if len(prs) == 0 {
		return prof, nil
	}

	// Build Profile from samples, locations and mappings.
	for _, pr := range prs {
		prof.Sample = append(prof.Sample, pr.Samples...)
	}

	// Locations.
	for _, pr := range prs {
		prof.Location = append(prof.Location, pr.Locations...)
	}

	// User mappings.
	for _, pr := range prs {
		prof.Mapping = append(prof.Mapping, pr.UserMappings...)
	}

	// Kernel mappings.
	lastProfile := prs[len(prs)-1]
	lastProfile.KernelMapping.ID = uint64(len(prof.Mapping)) + 1
	prof.Mapping = append(prof.Mapping, lastProfile.KernelMapping)

	// Symbolized functions.
	for _, pr := range prs {
		if len(pr.Functions) > 0 {
			prof.Function = pr.Functions
		}
	}

	return prof, nil
}
