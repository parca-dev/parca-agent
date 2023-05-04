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

package profiler

import (
	"time"

	"github.com/google/pprof/profile"
)

// TODO(kakkoyun): We can use a pool of pprof here.
// TODO(kakkoyun): Move to convert package.

// ConvertToPprof converts several per process Profile to a pprof Profile.
func ConvertToPprof(captureTime time.Time, periodNS int64, prs ...*Profile) (*profile.Profile, error) {
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
		for _, l := range pr.Locations {
			prof.Location = append(prof.Location, l.Location)
		}
	}

	// User mappings.
	for _, pr := range prs {
		// TODO(kakkoyun): Add the ID logic to here.
		prof.Mapping = append(prof.Mapping, pr.UserMappings.ConvertToPprof()...)
	}

	// Kernel mappings.
	lastProfile := prs[len(prs)-1]
	kernelMapping := lastProfile.KernelMapping.ConvertToPprof()
	kernelMapping.ID = uint64(len(prof.Mapping)) + 1
	prof.Mapping = append(prof.Mapping, kernelMapping)

	// Symbolized functions.
	for _, pr := range prs {
		// TODO(kakkoyun): Add the ID logic to the symbolized functions.
		for _, f := range pr.Functions {
			prof.Function = append(prof.Function, f.Function)
		}
	}

	return prof, nil
}
