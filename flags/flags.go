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

package flags

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/alecthomas/kong"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	_ "google.golang.org/grpc/encoding/proto"
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

	profilerStatusError    = "error"
	profilerStatusActive   = "active"
	profilerStatusInactive = "inactive"

	// This is the X in 2^(n + x) where n is the default hardcoded map size value
	defaultMapScaleFactor = 0
	// 1TB of executable address space
	maxMapScaleFactor = 8
)

func Parse() (Flags, error) {
	flags := Flags{}
	hostname, hostnameErr := os.Hostname() // hotnameErr handled below.
	kong.Parse(&flags, kong.Vars{
		"hostname":                       hostname,
		"default_cpu_sampling_frequency": strconv.Itoa(defaultCPUSamplingFrequency),
		"default_map_scale_factor":       strconv.Itoa(defaultMapScaleFactor),
		"max_map_scale_factor":           strconv.Itoa(maxMapScaleFactor),
		"default_memlock_rlimit":         "0", // No limit by default. (flag is deprecated)
	})

	if flags.Node == "" && hostnameErr != nil {
		return Flags{}, fmt.Errorf("failed to get hostname. Please set it with the --node flag: %w", hostnameErr)
	}

	flags.Log.ConfigureLogger()

	return flags, nil
}

type Flags struct {
	Log         FlagsLogs `embed:""                         prefix:"log-"`
	HTTPAddress string    `default:"127.0.0.1:7071"         help:"Address to bind HTTP server to."`
	Version     bool      `help:"Show application version."`

	EnvironmentType string `help:"The type of environment."`
	MachineID       string `help:"The machine ID."`

	OtelTags string `default:"" help:"Otel tags to attach to all traces."`
	Tracers  string `default:"all" help:"Tracers to enable."`

	Node          string `default:"${hostname}"               help:"The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name."`
	ConfigPath    string `default:""                          help:"Path to config file."`
	MemlockRlimit uint64 `default:"${default_memlock_rlimit}" help:"[deprecated] The value for the maximum number of bytes of memory that may be locked into RAM. It is used to ensure the agent can lock memory for eBPF maps. 0 means no limit."`

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

	ClockSyncInterval time.Duration `default:"3m" help:"How frequently to synchronize with the realtime clock."`

	DWARFUnwinding         FlagsDWARFUnwinding `embed:""        prefix:"dwarf-unwinding-"`
	PythonUnwindingDisable bool                `default:"false" help:"[deprecated] Disable Python unwinder."`
	RubyUnwindingDisable   bool                `default:"false" help:"[deprecated] Disable Ruby unwinder."`
	JavaUnwindingDisable   bool                `default:"true"  help:"[deprecated] Disable Java unwinder."`

	CollectCustomLabels bool `default:"false" help:"Attempt to collect custom labels (e.g. trace ID) from the process."`

	AnalyticsOptOut bool `default:"false" help:"Opt out of sending anonymous usage statistics."`

	Telemetry FlagsTelemetry `embed:"" prefix:"telemetry-"`
	Hidden    FlagsHidden    `embed:"" hidden:""           prefix:""`

	BPF FlagsBPF `embed:"" prefix:"bpf-"`

	OfflineMode     FlagsOfflineMode `embed:"" prefix:"offline-mode-"`
	OffCPUThreshold uint             `default:"0" help:"The per-mille probablity of off-CPU event being recorded."`
}

type ExitCode int

const (
	ExitSuccess ExitCode = 0
	ExitFailure ExitCode = 1

	// Go 'flag' package calls os.Exit(2) on flag parse errors, if ExitOnError is set
	ExitParseError ExitCode = 2
)

func ParseError(msg string, args ...interface{}) ExitCode {
	log.Errorf(msg, args...)
	return ExitParseError
}

func Failure(msg string, args ...interface{}) ExitCode {
	log.Errorf(msg, args...)
	return ExitFailure
}

func (f Flags) Validate() ExitCode {
	if f.EnvironmentType == "" && f.MachineID != "" {
		return ParseError("You can only specify the machine ID if you also provide the environment")
	}

	if f.BPF.MapScaleFactor > 8 {
		return ParseError("eBPF map scaling factor %d exceeds limit (max: %d)",
			f.BPF.MapScaleFactor, maxMapScaleFactor)
	}

	if f.BPF.VerifierLogLevel > 2 {
		return ParseError("Invalid eBPF verifier log level: %d", f.BPF.VerifierLogLevel)
	}

	if f.Profiling.ProbabilisticInterval < 1*time.Minute || f.Profiling.ProbabilisticInterval > 5*time.Minute {
		return ParseError("Invalid argument for probabilistic-interval: use " +
			"a duration between 1 and 5 minutes")
	}

	if f.Profiling.ProbabilisticThreshold < 1 ||
		f.Profiling.ProbabilisticThreshold > tracer.ProbabilisticThresholdMax {
		return ParseError("Invalid argument for probabilistic-threshold. Value "+
			"should be between 1 and %d", tracer.ProbabilisticThresholdMax)
	}

	if !f.Hidden.IgnoreUnsafeKernelVersion {
		major, minor, patch, err := tracer.GetCurrentKernelVersion()
		if err != nil {
			return Failure("Failed to get kernel version: %v", err)
		}

		var minMajor, minMinor uint32
		switch runtime.GOARCH {
		case "amd64":
			minMajor, minMinor = 4, 19
		case "arm64":
			// Older ARM64 kernel versions have broken bpf_probe_read.
			// https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47
			minMajor, minMinor = 5, 5
		default:
			return Failure("Unsupported architecture: %s", runtime.GOARCH)
		}

		if major < minMajor || (major == minMajor && minor < minMinor) {
			return Failure("Host Agent requires kernel version "+
				"%d.%d or newer but got %d.%d.%d", minMajor, minMinor, major, minor, patch)
		}
	}

	if len(f.OfflineMode.StoragePath) > 0 && !f.OfflineMode.Upload && (len(f.RemoteStore.Address) > 0 || len(f.OTLP.Address) > 0) {
		return ParseError("Specified both offline mode and a remote store; this configuration is invalid.")
	}

	if f.OfflineMode.Upload && len(f.OfflineMode.StoragePath) == 0 {
		return ParseError("Specified --offline-mode-upload without --offline-mode-storage-path.")
	}

	if f.OffCPUThreshold > support.OffCPUThresholdMax {
		return ParseError("Off-CPU threshold %d exceeds limit (max: %d)",
			f.OffCPUThreshold, support.OffCPUThresholdMax)
	}

	return ExitSuccess
}

// FlagsLocalStore provides local store configuration flags.
type FlagsLogs struct {
	Level  string `default:"info"   enum:"error,warn,info,debug" help:"Log level."`
	Format string `default:"logfmt" enum:"logfmt,json"           help:"Configure if structured logging as JSON or as logfmt"`
}

func (f FlagsLogs) logrusLevel() log.Level {
	switch f.Level {
	case "error":
		return log.ErrorLevel
	case "warn":
		return log.WarnLevel
	case "info":
		return log.InfoLevel
	case "debug":
		return log.DebugLevel
	default:
		return log.InfoLevel
	}
}

func (f FlagsLogs) logrusFormatter() log.Formatter {
	switch f.Format {
	case "logfmt":
		return &log.TextFormatter{}
	case "json":
		return &log.JSONFormatter{}
	default:
		return &log.TextFormatter{}
	}
}

func (f FlagsLogs) ConfigureLogger() {
	log.SetLevel(f.logrusLevel())
	log.SetFormatter(f.logrusFormatter())
}

// FlagsOTLP provides OTLP configuration flags.
type FlagsOTLP struct {
	Address  string `help:"The endpoint to send OTLP traces to."`
	Exporter string `default:"grpc"                              enum:"grpc,http,stdout" help:"The OTLP exporter to use."`
}

// FlagsProfiling provides profiling configuration flags.
type FlagsProfiling struct {
	Duration             time.Duration `default:"5s"                                help:"The agent profiling duration to use. Leave this empty to use the defaults."`
	CPUSamplingFrequency int           `default:"${default_cpu_sampling_frequency}" help:"The frequency at which profiling data is collected, e.g., 19 samples per second."`

	PerfEventBufferPollInterval       time.Duration `default:"250ms" help:"[deprecated] The interval at which the perf event buffer is polled for new events."`
	PerfEventBufferProcessingInterval time.Duration `default:"100ms" help:"[deprecated] The interval at which the perf event buffer is processed."`
	PerfEventBufferWorkerCount        int           `default:"4"     help:"[deprecated] The number of workers that process the perf event buffer."`

	ProbabilisticInterval  time.Duration `default:"1m" help:"Time interval for which probabilistic profiling will be enabled or disabled."`
	ProbabilisticThreshold uint          `default:"100" help:"If set to a value between 1 and 99 will enable probabilistic profiling: every probabilistic-interval a random number between 0 and 99 is chosen. If the given probabilistic-threshold is greater than this random number, the agent will collect profiles from this system for the duration of the interval."`

	EnableErrorFrames bool `default:"false" help:"Enable collection of error frames."`
}

// FlagsMetadata provides metadadata configuration flags.
type FlagsMetadata struct {
	ExternalLabels             map[string]string `help:"Label(s) to attach to all profiles."`
	ContainerRuntimeSocketPath string            `help:"The filesystem path to the container runtimes socket. Leave this empty to use the defaults."`

	DisableCaching       bool `default:"false" help:"[deprecated] Disable caching of metadata."`
	EnableProcessCmdline bool `default:"false" help:"[deprecated] Add /proc/[pid]/cmdline as a label, which may expose sensitive information like secrets in profiling data."`
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

	BatchWriteInterval time.Duration `default:"10s"   help:"[deprecated] Interval between batch remote client writes. Leave this empty to use the default value of 10s."`
	RPCLoggingEnable   bool          `default:"false" help:"[deprecated] Enable gRPC logging."`
	RPCUnaryTimeout    time.Duration `default:"5m"    help:"[deprecated] Maximum timeout window for unary gRPC requests including retries."`

	GRPCMaxCallRecvMsgSize   int           `default:"33554432" help:"The maximum message size the client can receive."`
	GRPCMaxCallSendMsgSize   int           `default:"33554432" help:"The maximum message size the client can send."`
	GRPCStartupBackoffTime   time.Duration `default:"1m" help:"The time between failed gRPC requests during startup phase."`
	GRPCConnectionTimeout    time.Duration `default:"3s" help:"The timeout duration for gRPC connection establishment."`
	GRPCMaxConnectionRetries uint32        `default:"5" help:"The maximum number of retries to establish a gRPC connection."`
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
	UploadQueueSize       uint32        `default:"4096"           help:"The maximum number of debuginfo upload requests to queue. If the queue is full, new requests will be dropped."`
}

// FlagsSymbolizer contains flags to configure symbolization.
type FlagsSymbolizer struct {
	JITDisable bool `help:"[deprecated] Disable JIT symbolization."`
}

// FlagsDWARFUnwinding contains flags to configure DWARF unwinding.
type FlagsDWARFUnwinding struct {
	Disable bool `help:"[deprecated] Do not unwind using .eh_frame information."`
	Mixed   bool `default:"true"                                    help:"[deprecated] Unwind using .eh_frame information and frame pointers."`
}

type FlagsTelemetry struct {
	DisablePanicReporting bool  `default:"false"`
	StderrBufferSizeKb    int64 `default:"4096"`
}

type FlagsObjectFilePool struct {
	EvictionPolicy string `default:"lru" enum:"lru,lfu"                                                                                                                                                                                          help:"[deprecated] The eviction policy to use for the object file pool."`
	Size           int    `default:"100" help:"[deprecated] The maximum number of object files to keep in the pool. This is used to avoid re-reading object files from disk. It keeps FDs open, so it should be kept in sync with ulimits. 0 means no limit."`
}

// FlagsHidden contains hidden flags used for debugging or running with untested configurations.
type FlagsHidden struct {
	AllowRunningAsNonRoot             bool `help:"Force running the Agent even if the user is not root. This will break a lot of the assumptions and result in the Agent malfunctioning."  hidden:""`
	AllowRunningInNonRootPIDNamespace bool `help:"Force running the Agent in a non 'root' PID namespace. This will break a lot of the assumptions and result in the Agent malfunctioning." hidden:""`

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
	MapScaleFactor   int    `default:"${default_map_scale_factor}" help:"Scaling factor for eBPF map sizes. Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. Default is ${default_map_scale_factor} corresponding to 4GB of executable address space, max is ${max_map_scale_factor}."`
	VerifierLogLevel uint32 `default:"0" help:"Log level of the eBPF verifier output (0,1,2). Default is 0."`
	VerifierLogSize  int    `default:"0" help:"[deprecated] Unused."`
}

type FlagsOfflineMode struct {
	StoragePath      string        `help:"Enables offline mode, with the data stored at the given path."`
	RotationInterval time.Duration `default:"10m" help:"How often to rotate and compress the offline mode log."`
	Upload           bool          `help:"Run the uploader for data written in offline mode."`
}
