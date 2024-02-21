// Copyright 2022-2024 The Parca Authors
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

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	pprofprofile "github.com/google/pprof/profile"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/model/relabel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/namespace"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
	parcapprof "github.com/parca-dev/parca-agent/pkg/pprof"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/vdso"
)

type Sample struct {
	Labels  model.LabelSet
	Profile *pprofprofile.Profile
}

type TestProfileStore struct {
	Samples []Sample
}

func NewTestProfileStore() *TestProfileStore {
	return &TestProfileStore{Samples: make([]Sample, 0)}
}

func (tpw *TestProfileStore) Store(_ context.Context, labels model.LabelSet, profile profile.Writer, _ []*profilestorepb.ExecutableInfo) error {
	p, ok := profile.(*pprofprofile.Profile)
	if !ok {
		return errors.New("profile is not a pprof profile")
	}
	tpw.Samples = append(tpw.Samples, Sample{
		Labels:  labels,
		Profile: p,
	})
	return nil
}

// SampleForProcess returns the first or last matching sample for a given PID.
func (tpw *TestProfileStore) SampleForProcess(pid int, last bool) *Sample { // nolint:unparam
	for i := range tpw.Samples {
		var sample Sample
		if last {
			sample = tpw.Samples[len(tpw.Samples)-1-i]
		} else {
			sample = tpw.Samples[i]
		}

		foundPid, err := strconv.Atoi(string(sample.Labels["pid"]))
		if err != nil {
			panic("label pid is not a valid integer")
		}

		if foundPid == pid {
			return &sample
		}
	}

	return nil
}

// IsRunningOnCI returns whether we might be running in a continuous integration environment. GitHub
// Actions and most other CI platforms set the CI environment variable.
func IsRunningOnCI() bool {
	_, ok := os.LookupEnv("CI")
	return ok
}

// ProfileDuration sets the profile runtime to a shorter time period
// when running outside of CI. The logic for this is that very loaded
// systems, such as GH actions might take a long time to spawn processes.
// By increasing the runtime we reduce the chance of flaky test executions,
// but we shouldn't have to pay this price during local dev.
func ProfileDuration() time.Duration {
	if IsRunningOnCI() {
		return 30 * time.Second
	}
	return 5 * time.Second
}

// ParsePrometheusMetricsEndpoint does some very light parsing of the metrics
// published in Prometheus.
func ParsePrometheusMetricsEndpoint(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		splittedLine := strings.Split(line, " ")
		if len(splittedLine) < 2 {
			continue
		}
		key := splittedLine[0]
		value := splittedLine[1]
		result[key] = value
	}
	return result
}

// WaitForServer waits up to 100ms * 5. Returns an error if the HTTP server
// is not reachable and a nil error if it is.
func WaitForServer(url string) error {
	for i := 0; i < 5; i++ {
		b, err := http.Get(url) //nolint: noctx,gosec
		if err == nil {
			b.Body.Close()
			return nil
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return errors.New("timed out waiting for HTTP server to start")
}

const (
	Arm64 = "arm64"
	Amd64 = "x86"
)

// Choose host architecture.
func ChooseArch() (string, error) {
	var arch string
	switch goruntime.GOARCH {
	case "arm64":
		arch = Arm64
	case "amd64":
		arch = Amd64
	default:
		return "", fmt.Errorf("unsupported architecture: %s", goruntime.GOARCH)
	}
	return arch, nil
}

func NewTestProfiler(
	logger log.Logger,
	reg *prometheus.Registry,
	ofp *objectfile.Pool,
	profileStore profiler.ProfileStore,
	tempDir string,
	config *cpu.Config,
	relabelConfig ...*relabel.Config,
) (*cpu.CPU, error) {
	loopDuration := 1 * time.Second
	disableJIT := false

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return nil, err
	}
	bpfProgramLoaded := make(chan bool, 1)

	var vdsoCache parcapprof.VDSOSymbolizer
	vdsoCache, err = vdso.NewCache(reg, ofp)
	if err != nil {
		vdsoCache = vdso.NoopCache{}
	}

	dbginfo := debuginfo.NoopDebuginfoManager{}
	cim := runtime.NewCompilerInfoManager(reg, ofp)
	labelsManager := labels.NewManager(
		logger,
		noop.NewTracerProvider().Tracer("test"),
		reg,
		[]metadata.Provider{
			metadata.Compiler(logger, reg, pfs, cim),
			metadata.Runtime(reg, pfs),
			metadata.Process(pfs),
			metadata.System(),
			metadata.PodHosts(),
		},
		relabelConfig,
		false,
		loopDuration,
	)

	optimizedSymtabs := filepath.Join(tempDir, "optimized_symtabs")
	if err := os.RemoveAll(optimizedSymtabs); err != nil {
		level.Warn(logger).Log("msg", "failed to remove optimized symtabs directory", "err", err)
	}
	if err := os.MkdirAll(optimizedSymtabs, 0o755); err != nil {
		level.Error(logger).Log("msg", "failed to create optimized symtabs directory", "err", err)
	}

	profiler := cpu.NewCPUProfiler(
		logger,
		reg,
		process.NewInfoManager(
			logger,
			noop.NewTracerProvider().Tracer("test"),
			reg,
			pfs,
			ofp,
			process.NewMapManager(reg, pfs, ofp),
			dbginfo,
			labelsManager,
			loopDuration,
			loopDuration,
		),
		cim,
		parcapprof.NewManager(
			logger,
			reg,
			ksym.NewKsym(logger, reg, tempDir),
			perf.NewPerfMapCache(logger, reg, namespace.NewCache(logger, reg, loopDuration), optimizedSymtabs, loopDuration),
			perf.NewJITDumpCache(logger, reg, optimizedSymtabs, loopDuration),
			vdsoCache,
			disableJIT,
		),
		profileStore,
		config,
		bpfProgramLoaded,
		ofp,
	)

	// Wait for the BPF program to be loaded.
	for len(bpfProgramLoaded) > 0 {
		<-bpfProgramLoaded
	}

	return profiler, nil
}
