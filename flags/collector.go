// Copyright 2026 The Parca Authors
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

package flags

import (
	"strings"
	"time"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
)

// reporterInterval is how often the tracer hands traces to the reporter.
// parca-agent has never exposed it as a flag.
const reporterInterval = 5 * time.Second

// CollectorConfig maps the flags onto the ebpf-profiler collector's config,
// so the profiler's own Validate decides which tracer settings are valid,
// including the minimum kernel version. Fields parca-agent has no flag for
// take the collector's defaults.
func (f Flags) CollectorConfig() *config.Config {
	return &config.Config{
		ReporterInterval:       reporterInterval,
		MonitorInterval:        f.Profiling.Duration,
		SamplesPerSecond:       f.Profiling.CPUSamplingFrequency,
		FrameCacheSize:         uint(pm.DefaultFrameCacheSize),
		ProbabilisticInterval:  f.Profiling.ProbabilisticInterval,
		ProbabilisticThreshold: f.Profiling.ProbabilisticThreshold,
		ClockSyncInterval:      f.ClockSyncInterval,
		SendErrorFrames:        f.Profiling.EnableErrorFrames,
		VerboseMode:            f.BPF.VerboseLogging,
		IncludeEnvVars:         strings.Join(f.IncludeEnvVar, ","),
		MapScaleFactor:         uint(f.BPF.MapScaleFactor), // negative wraps and fails Validate
		BPFVerifierLogLevel:    uint(f.BPF.VerifierLogLevel),
		NoKernelVersionCheck:   f.Hidden.IgnoreUnsafeKernelVersion,
		ErrorMode:              config.PropagateError,
	}
}
