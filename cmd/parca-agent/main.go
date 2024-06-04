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

package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	runtimepprof "runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/common-nighthawk/go-figure"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	okrun "github.com/oklog/run"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	telemetrypb "github.com/parca-dev/parca/gen/proto/go/parca/telemetry/v1alpha1"

	"github.com/armon/circbuf"
	vtproto "github.com/planetscale/vtprotobuf/codec/grpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promconfig "github.com/prometheus/common/config"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/zcalusic/sysinfo"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/automaxprocs/maxprocs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/analytics"
	"github.com/parca-dev/parca-agent/pkg/buildinfo"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/config"
	"github.com/parca-dev/parca-agent/pkg/cpuinfo"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/discovery"
	parcagrpc "github.com/parca-dev/parca-agent/pkg/grpc"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/namespace"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
	converter "github.com/parca-dev/parca-agent/pkg/pprof"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/pkg/rlimit"
	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/template"
	"github.com/parca-dev/parca-agent/pkg/tracer"
	"github.com/parca-dev/parca-agent/pkg/vdso"
)

var (
	version string
	commit  string
	date    string
	goArch  string
)

const (
	// Use `sudo bpftool map` to determine the size of the maps.
	defaultMemlockRLimit                   = 64 * 1024 * 1024  // ~64MB
	defaultMemlockRLimitWithDWARFUnwinding = 512 * 1024 * 1024 // ~512MB

	// We sample at 19Hz (19 times per second) because it is a prime number,
	// and primes are good to avoid collisions with other things
	// that may be happening periodically on a machine.
	// In particular, 100 samples per second means every 10ms
	// which is a frequency that may very well be used by user code,
	// so a CPU profile could show a periodic workload on-CPU 100% of the time
	// which is misleading.
	defaultCPUSamplingFrequency = 19
	// Setting the CPU sampling frequency too high can impact overall machine performance.
	maxAdvicedCPUSamplingFrequency = 150

	profilerStatusError    = "error"
	profilerStatusActive   = "active"
	profilerStatusInactive = "inactive"
)

type flags struct {
	Log         FlagsLogs `embed:""                         prefix:"log-"`
	HTTPAddress string    `default:"127.0.0.1:7071"         help:"Address to bind HTTP server to."`
	Version     bool      `help:"Show application version."`

	Node          string `default:"${hostname}"               help:"The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name."`
	ConfigPath    string `default:""                          help:"Path to config file."`
	MemlockRlimit uint64 `default:"${default_memlock_rlimit}" help:"The value for the maximum number of bytes of memory that may be locked into RAM. It is used to ensure the agent can lock memory for eBPF maps. 0 means no limit."`

	// pprof.
	MutexProfileFraction int `default:"0" help:"Fraction of mutex profile samples to collect."`
	BlockProfileRate     int `default:"0" help:"Sample rate for block profile."`

	Profiling      FlagsProfiling      `embed:"" prefix:"profiling-"`
	Metadata       FlagsMetadata       `embed:"" prefix:"metadata-"`
	LocalStore     FlagsLocalStore     `embed:"" prefix:"local-store-"`
	RemoteStore    FlagsRemoteStore    `embed:"" prefix:"remote-store-"`
	Debuginfo      FlagsDebuginfo      `embed:"" prefix:"debuginfo-"`
	Symbolizer     FlagsSymbolizer     `embed:"" prefix:"symbolizer-"`
	OTLP           FlagsOTLP           `embed:"" prefix:"otlp-"`
	ObjectFilePool FlagsObjectFilePool `embed:"" prefix:"object-file-pool-"`

	DWARFUnwinding         FlagsDWARFUnwinding `embed:""        prefix:"dwarf-unwinding-"`
	PythonUnwindingDisable bool                `default:"false" help:"Disable Python unwinder."`
	RubyUnwindingDisable   bool                `default:"false" help:"Disable Ruby unwinder."`
	JavaUnwindingDisable   bool                `default:"true"  help:"Disable Java unwinder."`

	CollectTraceID bool `default:"false" help:"Attempt to collect trace ID from the process."`

	AnalyticsOptOut bool `default:"false" help:"Opt out of sending anonymous usage statistics."`

	Telemetry FlagsTelemetry `embed:"" prefix:"telemetry-"`
	Hidden    FlagsHidden    `embed:"" hidden:""           prefix:""`

	BPF FlagsBPF `embed:"" prefix:"bpf-"`
	// Deprecated. Remove in few releases.
	VerboseBpfLogging bool `help:"[deprecated] Use --bpf-verbose-logging. Enable verbose BPF logging."`
}

// FlagsLocalStore provides local store configuration flags.
type FlagsLogs struct {
	Level  string `default:"info"   enum:"error,warn,info,debug" help:"Log level."`
	Format string `default:"logfmt" enum:"logfmt,json"           help:"Configure if structured logging as JSON or as logfmt"`
}

// FlagsOTLP provides OTLP configuration flags.
type FlagsOTLP struct {
	Address  string `help:"The endpoint to send OTLP traces to."`
	Exporter string `default:"grpc"                              enum:"grpc,http,stdout" help:"The OTLP exporter to use."`
}

// FlagsProfiling provides profiling configuration flags.
type FlagsProfiling struct {
	Duration             time.Duration `default:"10s"                               help:"The agent profiling duration to use. Leave this empty to use the defaults."`
	CPUSamplingFrequency uint64        `default:"${default_cpu_sampling_frequency}" help:"The frequency at which profiling data is collected, e.g., 19 samples per second."`

	PerfEventBufferPollInterval       time.Duration `default:"250ms" help:"The interval at which the perf event buffer is polled for new events."`
	PerfEventBufferProcessingInterval time.Duration `default:"100ms" help:"The interval at which the perf event buffer is processed."`
	PerfEventBufferWorkerCount        int           `default:"4"     help:"The number of workers that process the perf event buffer."`
}

// FlagsMetadata provides metadadata configuration flags.
type FlagsMetadata struct {
	ExternalLabels             map[string]string `help:"Label(s) to attach to all profiles."`
	ContainerRuntimeSocketPath string            `help:"The filesystem path to the container runtimes socket. Leave this empty to use the defaults."`

	DisableCaching       bool `default:"false" help:"Disable caching of metadata."`
	EnableProcessCmdline bool `default:"false" help:"Add /proc/[pid]/cmdline as a label, which may expose sensitive information like secrets in profiling data."`
}

// FlagsLocalStore provides local store configuration flags.
type FlagsLocalStore struct {
	Directory string `help:"The local directory to store the profiling data."`
}

// FlagsRemoteStore provides remote store configuration flags.
type FlagsRemoteStore struct {
	Address            string `help:"gRPC address to send profiles and symbols to."`
	BearerToken        string `kong:"help='Bearer token to authenticate with store.',env='PARCA_BEARER_TOKEN'"`
	BearerTokenFile    string `help:"File to read bearer token from to authenticate with store."`
	Insecure           bool   `help:"Send gRPC requests via plaintext instead of TLS."`
	InsecureSkipVerify bool   `help:"Skip TLS certificate verification."`

	BatchWriteInterval time.Duration `default:"10s"   help:"Interval between batch remote client writes. Leave this empty to use the default value of 10s."`
	RPCLoggingEnable   bool          `default:"false" help:"Enable gRPC logging."`
	RPCUnaryTimeout    time.Duration `default:"5m"    help:"Maximum timeout window for unary gRPC requests including retries."`
}

// FlagsDebuginfo contains flags to configure debuginfo.
type FlagsDebuginfo struct {
	Directories           []string      `default:"/usr/lib/debug" help:"Ordered list of local directories to search for debuginfo files."`
	TempDir               string        `default:"/tmp"           help:"The local directory path to store the interim debuginfo files."`
	Strip                 bool          `default:"true"           help:"Only upload information needed for symbolization. If false the exact binary the agent sees will be uploaded unmodified."`
	Compress              bool          `default:"false"          help:"Compress debuginfo files' DWARF sections before uploading."`
	UploadDisable         bool          `default:"false"          help:"Disable debuginfo collection and upload."`
	UploadMaxParallel     int           `default:"25"             help:"The maximum number of debuginfo upload requests to make in parallel."`
	UploadTimeoutDuration time.Duration `default:"2m"             help:"The timeout duration to cancel upload requests."`
	UploadCacheDuration   time.Duration `default:"5m"             help:"The duration to cache debuginfo upload responses for."`
	DisableCaching        bool          `default:"false"          help:"Disable caching of debuginfo."`
}

// FlagsSymbolizer contains flags to configure symbolization.
type FlagsSymbolizer struct {
	JITDisable bool `help:"Disable JIT symbolization."`
}

// FlagsDWARFUnwinding contains flags to configure DWARF unwinding.
type FlagsDWARFUnwinding struct {
	Disable bool `help:"Do not unwind using .eh_frame information."`
	Mixed   bool `default:"true"                                    help:"Unwind using .eh_frame information and frame pointers."`
}

type FlagsTelemetry struct {
	DisablePanicReporting bool  `default:"false"`
	StderrBufferSizeKb    int64 `default:"4096"`
}

type FlagsObjectFilePool struct {
	EvictionPolicy string `default:"lru" enum:"lru,lfu"                                                                                                                                                                                          help:"The eviction policy to use for the object file pool."`
	Size           int    `default:"100" help:"The maximum number of object files to keep in the pool. This is used to avoid re-reading object files from disk. It keeps FDs open, so it should be kept in sync with ulimits. 0 means no limit."`
}

// FlagsHidden contains hidden flags used for debugging or running with untested configurations.
type FlagsHidden struct {
	DebugProcessNames []string `help:"Only attach profilers to specified processes. comm name will be used to match the given matchers. Accepts Go regex syntax (https://pkg.go.dev/regexp/syntax)." hidden:""`

	AllowRunningAsNonRoot             bool `help:"Force running the Agent even if the user is not root. This will break a lot of the assumptions and result in the Agent malfunctioning."  hidden:""`
	AllowRunningInNonRootPIDNamespace bool `help:"Force running the Agent in a non 'root' PID namespace. This will break a lot of the assumptions and result in the Agent malfunctioning." hidden:""`

	EnablePythonUnwinding bool `default:"false" help:"[deprecated] Python unwinder enabled by default. Use --python-unwinding-disable to disable it." hidden:""`
	EnableRubyUnwinding   bool `default:"false" help:"[deprecated] Ruby unwinder enabled by default. Use --ruby-unwinding-disable to disable it."     hidden:""`

	ForcePanic bool `default:"false" help:"Panics the agent in a goroutine to test that telemetry works." hidden:""`

	IgnoreUnsafeKernelVersion bool `default:"false" help:"Forces runs in kernels with known issues. This might freeze your system or cause other issues." hidden:""`

	RateLimitUnwindInfo         uint32 `default:"50" hidden:""`
	RateLimitProcessMappings    uint32 `default:"50" hidden:""`
	RateLimitRefreshProcessInfo uint32 `default:"50" hidden:""`
	RateLimitRead               uint32 `default:"50" hidden:""`
}

type FlagsBPF struct {
	VerboseLogging   bool   `help:"Enable verbose BPF logging."`
	EventsBufferSize uint32 `default:"8192"                     help:"Size in pages of the events buffer."`
}

var _ Profiler = (*profiler.NoopProfiler)(nil)

type Profiler interface {
	Name() string
	Run(ctx context.Context) error

	LastProfileStartedAt() time.Time
	LastError() error
	ProcessLastErrors() map[int]error
	FailedReasons() map[int]profiler.UnwindFailedReasons
}

func getRPCOptions(flags flags) []grpc.DialOption {
	var opts []grpc.DialOption

	if len(flags.RemoteStore.Address) > 0 {
		if flags.RemoteStore.Insecure {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		} else {
			config := &tls.Config{
				//nolint:gosec
				InsecureSkipVerify: flags.RemoteStore.InsecureSkipVerify,
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
		}

		if flags.RemoteStore.BearerToken != "" {
			opts = append(opts, grpc.WithPerRPCCredentials(
				parcagrpc.NewPerRequestBearerToken(flags.RemoteStore.BearerToken, flags.RemoteStore.Insecure)),
			)
		}

		if flags.RemoteStore.BearerTokenFile != "" {
			b, err := os.ReadFile(flags.RemoteStore.BearerTokenFile)
			if err != nil {
				panic(fmt.Errorf("failed to read bearer token from file: %w", err))
			}

			opts = append(opts, grpc.WithPerRPCCredentials(
				parcagrpc.NewPerRequestBearerToken(strings.TrimSpace(string(b)), flags.RemoteStore.Insecure)),
			)
		}
	}
	return opts
}

func getTelemetryMetadata(numCPU int) map[string]string {
	r := make(map[string]string)
	var si sysinfo.SysInfo
	si.GetSysInfo()

	r["git_commit"] = commit
	r["agent_version"] = version
	r["go_arch"] = goruntime.GOARCH
	r["kernel_release"] = si.Kernel.Release
	r["cpu_cores"] = strconv.Itoa(numCPU)

	return r
}

func main() {
	// Fetch build info such as the git revision we are based off
	buildInfo, err := buildinfo.FetchBuildInfo()
	if err != nil {
		fmt.Println("failed to fetch build info: %w", err) //nolint:forbidigo
		os.Exit(1)
	}

	if commit == "" {
		commit = buildInfo.VcsRevision
	}
	if date == "" {
		date = buildInfo.VcsTime
	}
	if goArch == "" {
		goArch = buildInfo.GoArch
	}

	hostname, hostnameErr := os.Hostname() // hotnameErr handled below.

	flags := flags{}
	kong.Parse(&flags, kong.Vars{
		"hostname":                       hostname,
		"default_memlock_rlimit":         "0", // No limit by default.
		"default_cpu_sampling_frequency": strconv.Itoa(defaultCPUSamplingFrequency),
	})

	logger := logger.NewLogger(flags.Log.Level, flags.Log.Format, "parca-agent")
	cpus, err := cpuinfo.OnlineCPUs()
	if err != nil {
		level.Error(logger).Log("msg", "failed to get set of online CPUs", "err", err)
		os.Exit(1)
	}

	if !flags.Telemetry.DisablePanicReporting && len(flags.RemoteStore.Address) > 0 {
		// Spawn ourselves in a child process but disabling telemetry in it.
		argsCopy := make([]string, 0, len(os.Args)+1)
		argsCopy = append(argsCopy, os.Args...)
		argsCopy = append(argsCopy, "--telemetry-disable-panic-reporting")

		buf, _ := circbuf.NewBuffer(flags.Telemetry.StderrBufferSizeKb)

		cmd := exec.Command(argsCopy[0], argsCopy[1:]...) //nolint:gosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = io.MultiWriter(os.Stderr, buf)

		// Run garbage collector to minimize the amount of memory that the parent
		// telemetry process uses.
		goruntime.GC()
		err := cmd.Run()
		if err != nil {
			level.Error(logger).Log("msg", "======================= unexpected error =======================")
			level.Error(logger).Log("msg", "last stderr", "last_stderr", buf.String())
			level.Error(logger).Log("msg", "================================================================")

			level.Error(logger).Log("msg", "about to report error to server")

			grpcLogger := log.NewNopLogger()
			tp := noop.NewTracerProvider()

			opts := getRPCOptions(flags)
			reg := prometheus.NewRegistry()

			conn, err := parcagrpc.Conn(grpcLogger, reg, tp, flags.RemoteStore.Address, flags.RemoteStore.RPCUnaryTimeout, opts...)
			if err != nil {
				level.Error(logger).Log("msg", "failed to connect to server", "error", err)
				os.Exit(1)
			}
			defer conn.Close()

			telemetryClient := telemetrypb.NewTelemetryServiceClient(conn)
			_, err = telemetryClient.ReportPanic(context.Background(), &telemetrypb.ReportPanicRequest{
				Stderr:   buf.String(),
				Metadata: getTelemetryMetadata(int(cpus.Num())),
			})
			if err != nil {
				level.Error(logger).Log("msg", "failed to call ReportPanic()", "error", err)
				os.Exit(1) //nolint: gocritic
			}

			level.Info(logger).Log("msg", "report sent successfully")

			if exiterr, ok := err.(*exec.ExitError); ok { //nolint: errorlint
				os.Exit(exiterr.ExitCode())
			}

			os.Exit(2)
		}

		os.Exit(0)
	}

	// This *must* be below the panic telemetry code.
	//
	// Should only be called for testing as it will do
	// what it says on the tin.
	if flags.Hidden.ForcePanic {
		go func() {
			time.Sleep(5 * time.Second)

			c := func() {
				panic("forced panic for testing purposes")
			}

			b := func() {
				c()
			}

			a := func() {
				b()
			}

			a()
		}()
	}

	if flags.Version {
		fmt.Printf("parca-agent, version %s (commit: %s, date: %s), arch: %s\n", version, commit, date, goArch) //nolint:forbidigo
		os.Exit(0)
	}

	level.Debug(logger).Log("msg", "parca-agent initialized",
		"version", version,
		"commit", commit,
		"date", date,
		"config", fmt.Sprintf("%+v", flags),
		"arch", goArch,
	)

	if flags.Node == "" && hostnameErr != nil {
		level.Error(logger).Log("msg", "failed to get hostname. Please set it with the --node flag", "err", hostnameErr)
		os.Exit(1)
	}

	if byteorder.GetHostByteOrder() == binary.BigEndian {
		level.Error(logger).Log("msg", "big endian CPUs are not supported")
		os.Exit(1)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewBuildInfoCollector(),
		collectors.NewGoCollector(
			collectors.WithGoCollectorRuntimeMetrics(collectors.MetricsAll),
		),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Name: "parca_agent_num_cpu",
		Help: "Number of CPUs",
	}).Set(float64(cpus.Num()))

	intro := figure.NewColorFigure("Parca Agent ", "roman", "yellow", true)
	intro.Print()

	if flags.Hidden.EnablePythonUnwinding {
		level.Warn(logger).Log("msg", "python unwinder is enabled by default, use --python-unwinding-disable to disable it")
	}
	if flags.Hidden.EnableRubyUnwinding {
		level.Warn(logger).Log("msg", "ruby unwinder is enabled by default, use --ruby-unwinding-disable to disable it")
	}

	// TODO(sylfrena): Entirely remove once full support for DWARF Unwinding Arm64 is added and production tested for a few days
	if goruntime.GOARCH == "arm64" {
		flags.DWARFUnwinding.Disable = false
		level.Info(logger).Log("msg", "ARM64 support is currently in beta. DWARF-based unwinding is not fully supported yet, see https://github.com/parca-dev/parca-agent/discussions/1376 for more details")
	}

	// Memlock rlimit 0 means no limit.
	if flags.MemlockRlimit != 0 {
		if flags.DWARFUnwinding.Disable {
			if flags.MemlockRlimit < defaultMemlockRLimit {
				level.Warn(logger).Log("msg", "memlock rlimit is too low. Setting it to the minimum required value", "min", defaultMemlockRLimit)
				flags.MemlockRlimit = defaultMemlockRLimit
			}
		} else {
			if flags.MemlockRlimit < defaultMemlockRLimitWithDWARFUnwinding {
				level.Warn(logger).Log("msg", "memlock rlimit is too low for DWARF unwinding. Setting it to the minimum required value", "min", defaultMemlockRLimitWithDWARFUnwinding)
				flags.MemlockRlimit = defaultMemlockRLimitWithDWARFUnwinding
			}
		}
	}

	if flags.Profiling.CPUSamplingFrequency <= 0 {
		level.Warn(logger).Log("msg", "cpu sampling frequency is too low. Setting it to the default value", "default", defaultCPUSamplingFrequency)
		flags.Profiling.CPUSamplingFrequency = defaultCPUSamplingFrequency
	} else if flags.Profiling.CPUSamplingFrequency > maxAdvicedCPUSamplingFrequency {
		level.Warn(logger).Log("msg", "cpu sampling frequency is too high, it can impact overall machine performance", "max", maxAdvicedCPUSamplingFrequency)
	}
	if flags.Profiling.CPUSamplingFrequency != defaultCPUSamplingFrequency {
		level.Warn(logger).Log("msg", "non default cpu sampling frequency is used, please consult https://github.com/parca-dev/parca-agent/blob/main/docs/design.md#cpu-sampling-frequency")
	}
	_, max, err := rlimit.Files()
	if err != nil {
		level.Warn(logger).Log("msg", "failed to get open file descriptor limit", "err", err)
	}
	if flags.ObjectFilePool.Size > ((max * 80) / 100) {
		level.Warn(logger).Log("msg", "object file pool size is too high, it can result in elevated memory usage", "size", flags.ObjectFilePool.Size, "max", max)
	}

	if _, err := maxprocs.Set(maxprocs.Logger(func(format string, a ...interface{}) {
		level.Info(logger).Log("msg", fmt.Sprintf(format, a...))
	})); err != nil {
		level.Warn(logger).Log("msg", "failed to set GOMAXPROCS automatically", "err", err)
	}

	// Set profiling rates.
	goruntime.SetBlockProfileRate(flags.BlockProfileRate)
	goruntime.SetMutexProfileFraction(flags.MutexProfileFraction)

	if err := run(logger, reg, flags, cpus); err != nil {
		level.Error(logger).Log("err", err)
	}
}

func isPowerOfTwo(n uint32) bool {
	if n == 0 {
		return false
	}
	return (n & (n - 1)) == 0
}

func run(logger log.Logger, reg *prometheus.Registry, flags flags, cpus cpuinfo.CPUSet) error {
	var (
		ctx = context.Background()

		cfg              = &config.Config{}
		configFileExists bool
	)

	if flags.ConfigPath == "" {
		level.Info(logger).Log("msg", "no config file provided, using default config")
	} else {
		configFileExists = true

		cfgFile, err := config.LoadFile(flags.ConfigPath)
		if err != nil {
			if !errors.Is(err, config.ErrEmptyConfig) {
				return fmt.Errorf("failed to read config: %w", err)
			}
			level.Warn(logger).Log("msg", "config file is empty, using default config")
		}
		if cfgFile != nil {
			level.Info(logger).Log("msg", "using config file", "path", flags.ConfigPath)
			cfg = cfgFile
		}
	}

	if flags.VerboseBpfLogging {
		return errors.New("this flag has been renamed to --bpf-verbose-logging")
	}

	if !isPowerOfTwo(flags.BPF.EventsBufferSize) {
		return errors.New("the BPF events buffer size should be a power of 2")
	}

	if flags.BPF.EventsBufferSize < 32 {
		return errors.New("the BPF events buffer is too small, should be at least 32 pages")
	}

	ok, doesRunInContainer, err := agent.PreflightChecks(
		flags.Hidden.AllowRunningAsNonRoot,
		flags.Hidden.AllowRunningInNonRootPIDNamespace,
		flags.Hidden.IgnoreUnsafeKernelVersion,
	)
	if !ok {
		return fmt.Errorf("preflight checks failed: %w", err)
	} else if err != nil {
		level.Warn(logger).Log("msg", "preflight checks failed", "err", err)
	}

	// Initialize tracing.
	var (
		exporter tracer.Exporter
		tp       trace.TracerProvider = noop.NewTracerProvider()
	)
	if flags.OTLP.Address != "" {
		var err error

		exporter, err = tracer.NewExporter(flags.OTLP.Exporter, flags.OTLP.Address)
		if err != nil {
			level.Error(logger).Log("msg", "failed to create tracing exporter", "err", err)
		}
		// NewExporter always returns a non-nil exporter and non-nil error.
		tp, err = tracer.NewProvider(ctx, version, exporter)
		if err != nil {
			level.Error(logger).Log("msg", "failed to create tracing provider", "err", err)
		}
	}

	profileStoreClient := agent.NewNoopProfileStoreClient()
	var debuginfoClient debuginfopb.DebuginfoServiceClient = debuginfo.NewNoopClient()

	if len(flags.RemoteStore.Address) > 0 {
		encoding.RegisterCodec(vtproto.Codec{})

		opts := getRPCOptions(flags)
		var grpcLogger log.Logger
		if !flags.RemoteStore.RPCLoggingEnable {
			grpcLogger = log.NewNopLogger()
		} else {
			grpcLogger = log.With(logger, "service", "gRPC/client")
		}
		conn, err := parcagrpc.Conn(grpcLogger, reg, tp, flags.RemoteStore.Address, flags.RemoteStore.RPCUnaryTimeout, opts...)
		if err != nil {
			return err
		}
		defer conn.Close()

		profileStoreClient = profilestorepb.NewProfileStoreServiceClient(conn)
		if !flags.Debuginfo.UploadDisable {
			debuginfoClient = debuginfopb.NewDebuginfoServiceClient(conn)
		} else {
			level.Info(logger).Log("msg", "debug information collection is disabled")
		}
	}

	var (
		g                   okrun.Group
		batchWriteClient    = agent.NewBatchWriteClient(logger, reg, profileStoreClient, flags.RemoteStore.BatchWriteInterval)
		localStorageEnabled = flags.LocalStore.Directory != ""
		profileListener     = agent.NewMatchingProfileListener(logger, batchWriteClient)
		profileStore        profiler.ProfileStore
	)

	// Run group of OTL exporter.
	if exporter != nil {
		logger := log.With(logger, "group", "otlp_exporter")
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting")
			defer level.Debug(logger).Log("msg", "stopped")

			if err := exporter.Start(ctx); err != nil {
				return fmt.Errorf("failed to start exporter: %w", err)
			}
			<-ctx.Done()
			return nil
		}, func(error) {
			level.Debug(logger).Log("msg", "cleaning up")
			defer level.Debug(logger).Log("msg", "cleanup finished")

			cancel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := exporter.Shutdown(ctx); err != nil {
				level.Error(logger).Log("msg", "failed to stop exporter", "err", err)
			}
		})
	}
	if !flags.AnalyticsOptOut {
		logger := log.With(logger, "group", "analytics")
		c := analytics.NewClient(
			tp,
			&http.Client{
				Transport: otelhttp.NewTransport(
					promconfig.NewUserAgentRoundTripper(
						"parca.dev/analytics-client/"+version,
						http.DefaultTransport),
				),
			},
			"parca-agent",
			time.Second*5,
		)

		var si sysinfo.SysInfo
		si.GetSysInfo()
		a := analytics.NewSender(
			logger,
			c,
			goruntime.GOARCH,
			int(cpus.Num()),
			version,
			si,
			doesRunInContainer,
		)
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			a.Run(ctx)
			return nil
		}, func(error) {
			cancel()
		})
	}

	if localStorageEnabled {
		profileStore = profiler.NewFileStore(flags.LocalStore.Directory)
		level.Info(logger).Log("msg", "local profile storage is enabled", "dir", flags.LocalStore.Directory)
	} else {
		profileStore = profiler.NewRemoteStore(logger, profileListener)

		// Run group of profile writer.
		{
			logger := log.With(logger, "group", "profile_writer")
			ctx, cancel := context.WithCancel(ctx)
			g.Add(func() error {
				level.Debug(logger).Log("msg", "starting")
				defer level.Debug(logger).Log("msg", "stopped")

				var err error
				runtimepprof.Do(ctx, runtimepprof.Labels("component", "remote_profile_writer"), func(ctx context.Context) {
					err = batchWriteClient.Run(ctx)
				})

				return err
			}, func(error) {
				level.Debug(logger).Log("msg", "cleaning up")
				defer level.Debug(logger).Log("msg", "cleanup finished")
				cancel()
			})
		}
	}

	logger.Log("msg", "starting...", "node", flags.Node, "store", flags.RemoteStore.Address)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	// Set the pprof profile handler only once we have loaded our BPF program to avoid
	// SIGPROFs [1] while we are loading it which results to increased loading time in
	// the best scenario, and failure to start the Agent in the worst case.
	//
	// This happens because our program takes a little time to load, mostly due to the
	// verification process, and if any signals are received during that time, the kernel
	// will abort the loading process [2] and return with -EAGAIN. Libbpf will retry up to
	// 5 times [3], and then return the error.
	//
	// - [1]: https://github.com/golang/go/blob/2ab0e04681332c88e1bfb5fe5a72d35c1c5aae8a/src/runtime/proc.go#L4658
	// - [2]: https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c#L13793-L13794
	// - [3]: https://github.com/libbpf/libbpf/blob/d73ecc91e1f9a2f2782e00f010a5a0d6abec09a4/src/bpf.h#L68-L69
	bpfProgramLoaded := make(chan bool, 1)
	go func() {
		<-bpfProgramLoaded
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	}()

	// Run group for discovery manager
	var discoveryManager *discovery.Manager
	{
		ctx, cancel := context.WithCancel(ctx)
		configs := discovery.Configs{
			discovery.NewPodConfig(
				flags.Node,
				flags.Metadata.ContainerRuntimeSocketPath,
			),
			discovery.NewSystemdConfig(),
		}
		discoveryManager = discovery.NewManager(logger, reg)
		if err := discoveryManager.ApplyConfig(ctx, map[string]discovery.Configs{"all": configs}); err != nil {
			cancel()
			return err
		}

		logger := log.With(logger, "group", "discovery_manager")
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting")
			defer level.Debug(logger).Log("msg", "stopped")

			var err error
			runtimepprof.Do(ctx, runtimepprof.Labels("component", "discovery_manager"), func(ctx context.Context) {
				err = discoveryManager.Run(ctx)
			})

			return err
		}, func(error) {
			level.Debug(logger).Log("msg", "cleaning up")
			defer level.Debug(logger).Log("msg", "cleanup finished")
			cancel()
		})
	}

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return fmt.Errorf("failed to open procfs: %w", err)
	}

	// Run group for process tree.
	psTree := process.NewTree(logger, pfs, flags.Profiling.Duration)
	{
		logger := log.With(logger, "group", "process_tree")
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting")
			defer level.Debug(logger).Log("msg", "stopped")

			return psTree.Run(ctx)
		}, func(error) {
			level.Debug(logger).Log("msg", "cleaning up")
			defer level.Debug(logger).Log("msg", "cleanup finished")
			cancel()
		})
	}

	// Run group for metadata discovery.
	discoveryMetadata := metadata.ServiceDiscovery(logger, discoveryManager.SyncCh(), psTree)
	{
		logger := log.With(logger, "group", "metadata_discovery")
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting")
			defer level.Debug(logger).Log("msg", "stopped")

			return discoveryMetadata.Run(ctx)
		}, func(error) {
			level.Debug(logger).Log("msg", "cleaning up")
			defer level.Debug(logger).Log("msg", "cleanup finished")
			cancel()
		})
	}

	ofp := objectfile.NewPool(logger, reg, flags.ObjectFilePool.EvictionPolicy, flags.ObjectFilePool.Size, flags.Profiling.Duration)
	defer ofp.Close() // Will make sure all the files are closed.

	compilerInfoManager := runtime.NewCompilerInfoManager(logger, reg, ofp)

	// All the metadata providers work best-effort.
	providers := []metadata.Provider{
		discoveryMetadata,
		metadata.Target(flags.Node, flags.Metadata.ExternalLabels),
		metadata.Compiler(logger, reg, pfs, compilerInfoManager),
		metadata.Runtime(reg, pfs),
		metadata.Process(pfs, flags.Metadata.EnableProcessCmdline),
		metadata.System(),
		metadata.PodHosts(),
	}

	labelsManager := labels.NewManager(
		log.With(logger, "component", "labels_manager"),
		tp.Tracer("labels_manager"),
		reg,
		providers,
		cfg.RelabelConfigs,
		flags.Metadata.DisableCaching,
		flags.Profiling.Duration, // Cache durations are calculated from profiling duration.
	)

	var vdsoResolver converter.VDSOSymbolizer
	vdsoResolver, err = vdso.NewCache(reg, ofp)
	if err != nil {
		vdsoResolver = vdso.NoopCache{}
		level.Debug(logger).Log("msg", "failed to initialize vdso cache", "err", err)
	}
	ditracer := tp.Tracer("debuginfo")
	finder := debuginfo.NewFinder(logger, ditracer, reg, flags.Debuginfo.Directories)
	defer finder.Close()
	var dbginfo process.DebuginfoManager
	if !flags.Debuginfo.UploadDisable {
		dbginfo = debuginfo.New(
			log.With(logger, "component", "debuginfo"),
			tp,
			ditracer,
			reg,
			ofp,
			debuginfoClient,
			debuginfo.ManagerConfig{
				UploadMaxParallel:     flags.Debuginfo.UploadMaxParallel,
				UploadTimeout:         flags.Debuginfo.UploadTimeoutDuration,
				CachingDisabled:       flags.Debuginfo.DisableCaching,
				DebugDirs:             flags.Debuginfo.Directories,
				StripDebuginfos:       flags.Debuginfo.Strip,
				CompressDWARFSections: flags.Debuginfo.Compress,
				TempDir:               flags.Debuginfo.TempDir,
			},
			finder,
		)
		defer dbginfo.Close()
	} else {
		dbginfo = debuginfo.NoopDebuginfoManager{}
	}

	processInfoManager := process.NewInfoManager(
		log.With(logger, "component", "process_info"),
		tp.Tracer("process_info"),
		reg,
		pfs,
		ofp,
		process.NewMapManager(
			reg,
			pfs,
			ofp,
		),
		dbginfo,
		labelsManager,
		flags.Profiling.Duration,
		flags.Debuginfo.UploadCacheDuration,
		compilerInfoManager,
	)
	{
		logger := log.With(logger, "group", "process_info_manager")
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting")
			defer level.Debug(logger).Log("msg", "stopped")

			return processInfoManager.Run(ctx)
		}, func(error) {
			cancel()
			processInfoManager.Close()
		})
	}

	optimizedSymtabs := filepath.Join(flags.Debuginfo.TempDir, "optimized_symtabs")
	if err := os.RemoveAll(optimizedSymtabs); err != nil {
		level.Warn(logger).Log("msg", "failed to remove optimized symtabs directory", "err", err)
	}
	if err := os.MkdirAll(optimizedSymtabs, 0o644); err != nil {
		return fmt.Errorf("failed to create optimized symtabs directory: %w", err)
	}

	nsCache := namespace.NewCache(logger, reg, flags.Profiling.Duration)

	profilers := []Profiler{
		cpu.NewCPUProfiler(
			log.With(logger, "component", "cpu_profiler"),
			reg,
			processInfoManager,
			compilerInfoManager,
			converter.NewManager(
				log.With(logger, "component", "converter_manager"),
				reg,
				ksym.NewKsym(logger, reg, flags.Debuginfo.TempDir),
				perf.NewPerfMapCache(logger, reg, nsCache, optimizedSymtabs, flags.Profiling.Duration),
				perf.NewJITDumpCache(logger, reg, optimizedSymtabs, flags.Profiling.Duration),
				vdsoResolver,
				flags.Symbolizer.JITDisable,
			),
			profileStore,
			&cpu.Config{
				ProfilingDuration:                 flags.Profiling.Duration,
				ProfilingSamplingFrequency:        flags.Profiling.CPUSamplingFrequency,
				PerfEventBufferPollInterval:       flags.Profiling.PerfEventBufferPollInterval,
				PerfEventBufferProcessingInterval: flags.Profiling.PerfEventBufferProcessingInterval,
				PerfEventBufferWorkerCount:        flags.Profiling.PerfEventBufferWorkerCount,
				MemlockRlimit:                     flags.MemlockRlimit,
				DebugProcessNames:                 flags.Hidden.DebugProcessNames,
				DWARFUnwindingDisabled:            flags.DWARFUnwinding.Disable,
				DWARFUnwindingMixedModeEnabled:    flags.DWARFUnwinding.Mixed,
				BPFVerboseLoggingEnabled:          flags.BPF.VerboseLogging,
				BPFEventsBufferSize:               flags.BPF.EventsBufferSize,
				PythonUnwindingEnabled:            !flags.PythonUnwindingDisable,
				RubyUnwindingEnabled:              !flags.RubyUnwindingDisable,
				JavaUnwindingEnabled:              !flags.JavaUnwindingDisable,
				RateLimitUnwindInfo:               flags.Hidden.RateLimitUnwindInfo,
				RateLimitProcessMappings:          flags.Hidden.RateLimitProcessMappings,
				RateLimitRefreshProcessInfo:       flags.Hidden.RateLimitRefreshProcessInfo,
				RateLimitRead:                     flags.Hidden.RateLimitRead,
				CollectTraceID:                    flags.CollectTraceID,
			},
			bpfProgramLoaded,
			ofp,
			cpus,
			finder,
		),
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthy" || r.URL.Path == "/ready" || r.URL.Path == "/favicon.ico" {
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			statusPage := template.StatusPage{
				ProfilingInterval:   flags.Profiling.Duration,
				ProfileLinksEnabled: !localStorageEnabled,
				Config:              cfg.String(),
			}

			processLastErrors := map[string]map[int]error{}
			unwindFailedReasons := map[string]map[int]profiler.UnwindFailedReasons{}

			for _, profiler := range profilers {
				statusPage.ActiveProfilers = append(statusPage.ActiveProfilers, template.ActiveProfiler{
					Name:           profiler.Name(),
					NextStartedAgo: time.Since(profiler.LastProfileStartedAt()).Round(10 * time.Millisecond),
					Error:          profiler.LastError(),
				})

				processLastErrors[profiler.Name()] = profiler.ProcessLastErrors()
				unwindFailedReasons[profiler.Name()] = profiler.FailedReasons()
			}

			processes, err := procfs.AllProcs()
			if err != nil {
				http.Error(w,
					"Failed to list processes: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}

			processStatuses := []template.Process{}
			for _, process := range processes {
				pid := process.PID
				var lastError error
				var link, profilingStatus string
				for _, prflr := range profilers {
					lbls, err := labelsManager.Labels(r.Context(), pid)
					if err != nil {
						level.Warn(logger).Log("msg", "failed to get labels", "pid", pid, "err", err)
						continue
					}
					if len(lbls) == 0 {
						continue
					}
					lbls = append(lbls, labels.ProfilerName(prflr.Name()))

					err, active := processLastErrors[prflr.Name()][pid]

					switch {
					case err != nil:
						lastError = err
						profilingStatus = profilerStatusError
					case active:
						profilingStatus = profilerStatusActive
					default:
						profilingStatus = profilerStatusInactive
					}
					failedReasons := unwindFailedReasons[prflr.Name()][pid]
					failedReasonsStrs := make([]string, 0)
					if failedReasons.PcNotCovered != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("PcNotCovered: %d", failedReasons.PcNotCovered))
					}
					if failedReasons.NoUnwindInfo != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("NoUnwindInfo: %d", failedReasons.NoUnwindInfo))
					}
					if failedReasons.MissedFilter != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("MissedFilter: %d", failedReasons.MissedFilter))
					}
					if failedReasons.MappingNotFound != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("MappingNotFound: %d", failedReasons.MappingNotFound))
					}
					if failedReasons.ChunkNotFound != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("ChunkNotFound: %d", failedReasons.ChunkNotFound))
					}
					if failedReasons.NullUnwindTable != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("NullUnwindTable: %d", failedReasons.NullUnwindTable))
					}
					if failedReasons.TableNotFound != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("TableNotFound: %d", failedReasons.TableNotFound))
					}
					if failedReasons.RbpFailed != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("RbpFailed: %d", failedReasons.RbpFailed))
					}
					if failedReasons.RaFailed != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("RaFailed: %d", failedReasons.RaFailed))
					}
					if failedReasons.UnsupportedFpAction != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("UnsupportedFpAction: %d", failedReasons.UnsupportedFpAction))
					}
					if failedReasons.UnsupportedCfa != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("UnsupportedCfa: %d", failedReasons.UnsupportedCfa))
					}
					if failedReasons.PreviousRspZero != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("PreviousRspZero: %d", failedReasons.PreviousRspZero))
					}
					if failedReasons.PreviousRipZero != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("PreviousRipZero: %d", failedReasons.PreviousRipZero))
					}
					if failedReasons.PreviousRbpZero != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("PreviousRbpZero: %d", failedReasons.PreviousRbpZero))
					}
					if failedReasons.InternalError != 0 {
						failedReasonsStrs = append(failedReasonsStrs, fmt.Sprintf("InternalError: %d", failedReasons.InternalError))
					}

					if !localStorageEnabled {
						q := url.Values{}
						q.Add("debug", "1")
						q.Add("query", lbls.String())

						link = "/query?" + q.Encode()
					}

					processStatuses = append(processStatuses, template.Process{
						PID:             pid,
						Profiler:        prflr.Name(),
						Labels:          lbls,
						Error:           lastError,
						Link:            link,
						ProfilingStatus: profilingStatus,
						FailedReasons:   failedReasonsStrs,
					})
				}
			}

			statusPage.Processes = processStatuses

			err = template.StatusPageTemplate.Execute(w, statusPage)
			if err != nil {
				_, err = w.Write([]byte("\n\nUnexpected error occurred while rendering status page: " + err.Error()))
				if err != nil {
					level.Error(logger).Log("msg", "failed to write error message to response", "err", err)
				}
			}

			return
		}

		if !localStorageEnabled && strings.HasPrefix(r.URL.Path, "/query") {
			query := r.URL.Query().Get("query")
			matchers, err := parser.ParseMetricSelector(query)
			if err != nil {
				http.Error(w,
					`query incorrectly formatted, expecting selector in form of: {name1="value1",name2="value2"}`,
					http.StatusBadRequest,
				)
				return
			}

			// We profile every ProfilingDuration so leaving 1s wiggle room. If after
			// ProfilingDuration+1s no profile has matched, then there is very likely no
			// profiler running that matches the label-set.
			timeout := flags.Profiling.Duration + time.Second

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			profile, err := profileListener.NextMatchingProfile(ctx, matchers)
			if profile == nil || errors.Is(err, context.Canceled) {
				http.Error(w, fmt.Sprintf(
					"No profile taken in the last %s that matches the requested label-matchers query. "+
						"Profiles are taken every %s so either the profiler matching the label-set has stopped profiling, "+
						"or the label-set was incorrect.",
					timeout, flags.Profiling.Duration,
				), http.StatusNotFound)
				return
			}
			if err != nil {
				http.Error(w, "Unexpected error occurred: "+err.Error(), http.StatusInternalServerError)
				return
			}

			v := r.URL.Query().Get("debug")
			if v == "1" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				q := url.Values{}
				q.Add("query", query)

				fmt.Fprintf(
					w,
					"<p><a title='May take up %s to retrieve' href='/query?%s'>Download Next Pprof</a></p>\n",
					flags.Profiling.Duration,
					q.Encode(),
				)
				fmt.Fprint(w, "<code><pre>\n")
				fmt.Fprint(w, profile.String())
				fmt.Fprint(w, "\n</pre></code>")
				return
			}

			w.Header().Set("Content-Type", "application/vnd.google.protobuf+gzip")
			w.Header().Set("Content-Disposition", "attachment;filename=profile.pb.gz")
			err = profile.Write(w)
			if err != nil {
				level.Error(logger).Log("msg", "failed to write profile", "err", err)
			}
			return
		}

		http.NotFound(w, r)
	})

	// Run profilers.
	{
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		for _, p := range profilers {
			logger := log.With(logger, "group", "profiler/"+p.Name())
			g.Add(func() error {
				level.Debug(logger).Log("msg", "starting", "name", p.Name())
				defer level.Debug(logger).Log("msg", "stopped", "profiler", p.Name())

				var err error
				runtimepprof.Do(ctx, runtimepprof.Labels("component", p.Name()), func(ctx context.Context) {
					err = p.Run(ctx)
				})

				return err
			}, func(error) {
				level.Debug(logger).Log("msg", "cleaning up")
				defer level.Debug(logger).Log("msg", "cleanup finished")

				cancel()
			})
		}
	}

	// Run group for http server.
	{
		srv := &http.Server{
			Addr:         flags.HTTPAddress,
			Handler:      mux,
			ReadTimeout:  5 * time.Second, // TODO: Make this configurable.
			WriteTimeout: time.Minute,     // TODO: Make this configurable.
		}

		logger := log.With(logger, "group", "http_server")
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting")
			defer level.Debug(logger).Log("msg", "stopped")

			var err error
			runtimepprof.Do(ctx, runtimepprof.Labels("component", "http_server"), func(_ context.Context) {
				err = srv.ListenAndServe()
			})

			return err
		}, func(error) {
			level.Debug(logger).Log("msg", "cleaning up")
			defer level.Debug(logger).Log("msg", "cleanup finished")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := srv.Shutdown(ctx); err != nil {
				level.Error(logger).Log("msg", "failed to shutdown http server", "err", err)
			}
		})
	}

	// Run group for config reloader.
	if configFileExists {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		reloaders := []config.ComponentReloader{
			{
				// Used by UI
				Name: "main",
				Reloader: func(newCfg *config.Config) error {
					cfg = newCfg
					return nil
				},
			},
			{
				Name: "labels",
				Reloader: func(cfg *config.Config) error {
					return labelsManager.ApplyConfig(cfg.RelabelConfigs)
				},
			},
		}

		cfgReloader, err := config.NewConfigReloader(logger, reg, flags.ConfigPath, reloaders)
		if err != nil {
			level.Error(logger).Log("msg", "failed to instantiate config file reloader", "err", err)
			return err
		}

		logger := log.With(logger, "group", "config_file_reloader")
		g.Add(
			func() error {
				level.Debug(logger).Log("msg", "starting")
				defer level.Debug(logger).Log("msg", "stopped")

				var err error
				runtimepprof.Do(ctx, runtimepprof.Labels("component", "config_file_reloader"), func(_ context.Context) {
					err = cfgReloader.Run(ctx)
				})

				return err
			},
			func(error) {
				level.Debug(logger).Log("msg", "cleaning up")
				defer level.Debug(logger).Log("msg", "cleanup finished")
				cancel()
			},
		)
	}

	// Run group for signal handler.
	g.Add(okrun.SignalHandler(ctx, os.Interrupt, os.Kill))

	return g.Run()
}
