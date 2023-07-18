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

package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"runtime"
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
	vtproto "github.com/planetscale/vtprotobuf/codec/grpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promconfig "github.com/prometheus/common/config"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/zcalusic/sysinfo"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
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
	"github.com/parca-dev/parca-agent/pkg/kernel"
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

	Node               string `default:"${hostname}"               help:"The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name."`
	ConfigPath         string `default:""                          help:"Path to config file."`
	MemlockRlimit      uint64 `default:"${default_memlock_rlimit}" help:"The value for the maximum number of bytes of memory that may be locked into RAM. It is used to ensure the agent can lock memory for eBPF maps. 0 means no limit."`
	ObjectFilePoolSize int    `default:"512"                       help:"The maximum number of object files to keep in the pool. This is used to avoid re-reading object files from disk. It keeps FDs open, so it should be kept in sync with ulimits. 0 means no limit."`

	// pprof.
	MutexProfileFraction int `default:"0" help:"Fraction of mutex profile samples to collect."`
	BlockProfileRate     int `default:"0" help:"Sample rate for block profile."`

	Profiling      FlagsProfiling      `embed:"" prefix:"profiling-"`
	Metadata       FlagsMetadata       `embed:"" prefix:"metadata-"`
	LocalStore     FlagsLocalStore     `embed:"" prefix:"local-store-"`
	RemoteStore    FlagsRemoteStore    `embed:"" prefix:"remote-store-"`
	Debuginfo      FlagsDebuginfo      `embed:"" prefix:"debuginfo-"`
	Symbolizer     FlagsSymbolizer     `embed:"" prefix:"symbolizer-"`
	DWARFUnwinding FlagsDWARFUnwinding `embed:"" prefix:"dwarf-unwinding-"`
	OTLP           FlagsOTLP           `embed:"" prefix:"otlp-"`

	AnalyticsOptOut bool `default:"false" help:"Opt out of sending anonymous usage statistics."`

	Hidden FlagsHidden `embed:"" hidden:"" prefix:""`

	// TODO: Move to FlagsBPF once we have more flags.
	VerboseBpfLogging bool `help:"Enable verbose BPF logging."`
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

	DisableCaching bool `default:"false" help:"Disable caching of metadata."`
}

// FlagsLocalStore provides local store configuration flags.
type FlagsLocalStore struct {
	Directory string `help:"The local directory to store the profiling data."`
}

// FlagsRemoteStore provides remote store configuration flags.
type FlagsRemoteStore struct {
	Address            string `help:"gRPC address to send profiles and symbols to."`
	BearerToken        string `help:"Bearer token to authenticate with store."`
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
	Mixed   bool `default:"true"                                    help:"Unwind using .eh_frame information and frame pointers"`
}

// FlagsHidden contains hidden flags. Hidden debug flags (only for debugging).
type FlagsHidden struct {
	DebugProcessNames       []string `help:"Only attach profilers to specified processes. comm name will be used to match the given matchers. Accepts Go regex syntax (https://pkg.go.dev/regexp/syntax)." hidden:""`
	DebugNormalizeAddresses bool     `default:"true"                                                                                                                                                       help:"Normalize sampled addresses." hidden:""`
}

var _ Profiler = (*profiler.NoopProfiler)(nil)

type Profiler interface {
	Name() string
	Run(ctx context.Context) error

	LastProfileStartedAt() time.Time
	LastError() error
	ProcessLastErrors() map[int]error
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

	if flags.Version {
		fmt.Printf("parca-agent, version %s (commit: %s, date: %s), arch: %s\n", version, commit, date, goArch) //nolint:forbidigo
		os.Exit(0)
	}

	logger := logger.NewLogger(flags.Log.Level, flags.Log.Format, "parca-agent")
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
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	intro := figure.NewColorFigure("Parca Agent ", "roman", "yellow", true)
	intro.Print()

	if runtime.GOARCH == "arm64" {
		flags.DWARFUnwinding.Disable = true
		level.Info(logger).Log("msg", "ARM64 support is currently in beta. DWARF-based unwinding is not supported yet, see https://github.com/parca-dev/parca-agent/discussions/1376 for more details")
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
	if flags.ObjectFilePoolSize > ((max * 80) / 100) {
		level.Warn(logger).Log("msg", "object file pool size is too high, it can impact overall machine performance", "size", flags.ObjectFilePoolSize, "max", max)
	}

	if _, err := maxprocs.Set(maxprocs.Logger(func(format string, a ...interface{}) {
		level.Info(logger).Log("msg", fmt.Sprintf(format, a...))
	})); err != nil {
		level.Warn(logger).Log("msg", "failed to set GOMAXPROCS automatically", "err", err)
	}

	// Set profiling rates.
	runtime.SetBlockProfileRate(flags.BlockProfileRate)
	runtime.SetMutexProfileFraction(flags.MutexProfileFraction)

	if err := run(logger, reg, flags); err != nil {
		level.Error(logger).Log("err", err)
	}
}

func run(logger log.Logger, reg *prometheus.Registry, flags flags) error {
	var (
		ctx = context.Background()

		cfg              = &config.Config{}
		configFileExists bool
	)

	if flags.ConfigPath != "" {
		configFileExists = true

		cfgFile, err := config.LoadFile(flags.ConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read config: %w", err)
		}
		cfg = cfgFile
	}

	// Initialize tracing.
	var (
		exporter tracer.Exporter
		tp       = trace.NewNoopTracerProvider()
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

	isContainer, err := isInContainer()
	if err != nil {
		level.Warn(logger).Log("msg", "failed to check if running in container", "err", err)
	}

	if isContainer {
		level.Info(logger).Log(
			"msg", "running in a container, need to access the host kernel config.",
		)
	}

	if err := kernel.CheckBPFEnabled(); err != nil {
		// TODO: Add a more definitive test for the cases kconfig fails.
		// - https://github.com/libbpf/libbpf/blob/1714037104da56308ddb539ae0a362a9936121ff/src/libbpf.c#L4396-L4429
		level.Warn(logger).Log("msg", "failed to determine if eBPF is supported, host kernel might not support eBPF", "err", err)
	} else {
		level.Info(logger).Log("msg", "eBPF is supported and enabled by the host kernel")
	}

	profileStoreClient := agent.NewNoopProfileStoreClient()
	var debuginfoClient debuginfopb.DebuginfoServiceClient = debuginfo.NewNoopClient()

	if len(flags.RemoteStore.Address) > 0 {
		encoding.RegisterCodec(vtproto.Codec{})

		var opts []grpc.DialOption
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
				return fmt.Errorf("failed to read bearer token from file: %w", err)
			}
			opts = append(opts, grpc.WithPerRPCCredentials(
				parcagrpc.NewPerRequestBearerToken(strings.TrimSpace(string(b)), flags.RemoteStore.Insecure)),
			)
		}

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
		batchWriteClient    = agent.NewBatchWriteClient(logger, reg, profileStoreClient, flags.RemoteStore.BatchWriteInterval, flags.Hidden.DebugNormalizeAddresses)
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
						fmt.Sprintf("parca.dev/analytics-client/%s", version),
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
			runtime.GOARCH,
			cpuinfo.NumCPU(),
			version,
			si,
			isContainer,
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
		profileStore = profiler.NewRemoteStore(logger, profileListener, flags.Hidden.DebugNormalizeAddresses)

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

	ofp := objectfile.NewPool(logger, reg, flags.ObjectFilePoolSize, flags.Profiling.Duration)
	defer ofp.Close() // Will make sure all the files are closed.

	nsCache := namespace.NewCache(logger, reg, flags.Profiling.Duration)

	labelsManager := labels.NewManager(
		log.With(logger, "component", "labels_manager"),
		tp.Tracer("labels_manager"),
		reg,
		// All the metadata providers work best-effort.
		[]metadata.Provider{
			discoveryMetadata,
			metadata.Target(flags.Node, flags.Metadata.ExternalLabels),
			metadata.Compiler(logger, reg, ofp),
			metadata.Process(pfs),
			metadata.Java(logger, nsCache),
			metadata.Ruby(pfs, reg, ofp),
			metadata.Python(pfs, reg, ofp),
			metadata.System(),
			metadata.PodHosts(),
		},
		cfg.RelabelConfigs,
		flags.Metadata.DisableCaching,
		flags.Profiling.Duration, // Cache durations are calculated from profiling duration.
	)

	var vdsoResolver converter.VDSOSymbolizer
	vdsoResolver, err = vdso.NewCache(reg, ofp)
	if err != nil {
		vdsoResolver = vdso.NoopCache{}
		level.Warn(logger).Log("msg", "failed to initialize vdso cache", "err", err)
	}

	var dbginfo process.DebuginfoManager
	if !flags.Debuginfo.UploadDisable {
		dbginfo = debuginfo.New(
			log.With(logger, "component", "debuginfo"),
			tp,
			reg,
			ofp,
			debuginfoClient,
			flags.Debuginfo.UploadMaxParallel,
			flags.Debuginfo.UploadTimeoutDuration,
			flags.Debuginfo.DisableCaching,
			flags.Debuginfo.Directories,
			flags.Debuginfo.Strip,
			flags.Debuginfo.TempDir,
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
			flags.Hidden.DebugNormalizeAddresses,
		),
		dbginfo,
		labelsManager,
		flags.Profiling.Duration,
		flags.Debuginfo.UploadCacheDuration,
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

	profilers := []Profiler{
		cpu.NewCPUProfiler(
			log.With(logger, "component", "cpu_profiler"),
			reg,
			processInfoManager,
			converter.NewManager(
				log.With(logger, "component", "converter_manager"),
				reg,
				ksym.NewKsym(logger, reg, flags.Debuginfo.TempDir),
				perf.NewPerfMapCache(logger, reg, nsCache, flags.Profiling.Duration),
				perf.NewJitdumpCache(logger, reg, flags.Profiling.Duration),
				vdsoResolver,
				flags.Symbolizer.JITDisable,
			),
			profileStore,
			flags.Profiling.Duration,
			flags.Profiling.CPUSamplingFrequency,
			flags.Profiling.PerfEventBufferPollInterval,
			flags.Profiling.PerfEventBufferProcessingInterval,
			flags.Profiling.PerfEventBufferWorkerCount,
			flags.MemlockRlimit,
			flags.Hidden.DebugProcessNames,
			flags.DWARFUnwinding.Disable,
			flags.DWARFUnwinding.Mixed,
			flags.VerboseBpfLogging,
			bpfProgramLoaded,
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

			for _, profiler := range profilers {
				statusPage.ActiveProfilers = append(statusPage.ActiveProfilers, template.ActiveProfiler{
					Name:           profiler.Name(),
					NextStartedAgo: time.Since(profiler.LastProfileStartedAt()).Round(10 * time.Millisecond),
					Error:          profiler.LastError(),
				})

				processLastErrors[profiler.Name()] = profiler.ProcessLastErrors()
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

					if !localStorageEnabled {
						q := url.Values{}
						q.Add("debug", "1")
						q.Add("query", lbls.String())

						link = fmt.Sprintf("/query?%s", q.Encode())
					}

					processStatuses = append(processStatuses, template.Process{
						PID:             pid,
						Profiler:        prflr.Name(),
						Labels:          lbls,
						Error:           lastError,
						Link:            link,
						ProfilingStatus: profilingStatus,
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

const containerCgroupPath = "/proc/1/cgroup"

// isInContainer returns true is the process is running in a container
// TODO: Add a container detection via Sched to cover more scenarios
// https://man7.org/linux/man-pages/man7/sched.7.html
func isInContainer() (bool, error) {
	f, err := os.Open(containerCgroupPath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	b := make([]byte, 1024)
	i, err := f.Read(b)
	if err != nil {
		return false, err
	}

	switch {
	// CGROUP V1 docker container
	case strings.Contains(string(b[:i]), "cpuset:/docker"):
		return true, nil
	// CGROUP V2 docker container
	case strings.Contains(string(b[:i]), "0::/\n"):
		return true, nil
	// k8s container
	case strings.Contains(string(b[:i]), "cpuset:/kubepods"):
		return true, nil
	}

	return false, nil
}
