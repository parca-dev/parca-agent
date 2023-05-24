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
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	okrun "github.com/oklog/run"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	vtproto "github.com/planetscale/vtprotobuf/codec/grpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/promql/parser"
	"go.uber.org/automaxprocs/maxprocs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto"

	"github.com/parca-dev/parca-agent/pkg/address"
	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/buildinfo"
	"github.com/parca-dev/parca-agent/pkg/byteorder"
	"github.com/parca-dev/parca-agent/pkg/config"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/kconfig"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/metadata/labels"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/pkg/rlimit"
	"github.com/parca-dev/parca-agent/pkg/symbol"
	"github.com/parca-dev/parca-agent/pkg/template"
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
	Log         FlagsLogs `embed:"" prefix:"log-"`
	HTTPAddress string    `kong:"help='Address to bind HTTP server to.',default=':7071'"`
	Version     bool      `help:"Show application version."`

	Node          string `kong:"help='The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name.',default='${hostname}'"`
	ConfigPath    string `default:"" help:"Path to config file."`
	MemlockRlimit uint64 `default:"${default_memlock_rlimit}" help:"The value for the maximum number of bytes of memory that may be locked into RAM. It is used to ensure the agent can lock memory for eBPF maps. 0 means no limit."`

	Profiling      FlagsProfiling      `embed:"" prefix:"profiling-"`
	Metadata       FlagsMetadata       `embed:"" prefix:"metadata-"`
	LocalStore     FlagsLocalStore     `embed:"" prefix:"local-store-"`
	RemoteStore    FlagsRemoteStore    `embed:"" prefix:"remote-store-"`
	Debuginfo      FlagsDebuginfo      `embed:"" prefix:"debuginfo-"`
	Symbolizer     FlagsSymbolizer     `embed:"" prefix:"symbolizer-"`
	DWARFUnwinding FlagsDWARFUnwinding `embed:"" prefix:"dwarf-unwinding-"`

	Hidden FlagsHidden `embed:"" prefix:"" hidden:""`

	// TODO: Move to FlagsBPF once we have more flags.
	VerboseBpfLogging bool `kong:"help='Enable verbose BPF logging.'"`
}

// FlagsLocalStore provides local store configuration flags.
type FlagsLogs struct {
	Level  string `enum:"error,warn,info,debug" default:"info" help:"Log level."`
	Format string `enum:"logfmt,json" default:"logfmt" help:"Configure if structured logging as JSON or as logfmt"`
}

// FlagsProfiling provides profiling configuration flags.
type FlagsProfiling struct {
	Duration             time.Duration `kong:"help='The agent profiling duration to use. Leave this empty to use the defaults.',default='10s'"`
	CPUSamplingFrequency uint64        `kong:"help='The frequency at which profiling data is collected, e.g., 19 samples per second.',default='${default_cpu_sampling_frequency}'"`
}

// FlagsMetadata provides metadadata configuration flags.
type FlagsMetadata struct {
	ExternalLabels             map[string]string `kong:"help='Label(s) to attach to all profiles.'"`
	ContainerRuntimeSocketPath string            `kong:"help='The filesystem path to the container runtimes socket. Leave this empty to use the defaults.'"`
	DisableCaching             bool              `kong:"help='Disable caching of metadata.',default='false'"`
}

// FlagsLocalStore provides local store configuration flags.
type FlagsLocalStore struct {
	Directory string `kong:"help='The local directory to store the profiling data.'"`
}

// FlagsRemoteStore provides remote store configuration flags.
type FlagsRemoteStore struct {
	Address                string        `kong:"help='gRPC address to send profiles and symbols to.'"`
	BearerToken            string        `kong:"help='Bearer token to authenticate with store.'"`
	BearerTokenFile        string        `kong:"help='File to read bearer token from to authenticate with store.'"`
	Insecure               bool          `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
	InsecureSkipVerify     bool          `kong:"help='Skip TLS certificate verification.'"`
	DebuginfoUploadDisable bool          `kong:"help='Disable debuginfo collection and upload.',default='false'"`
	BatchWriteInterval     time.Duration `kong:"help='Interval between batch remote client writes. Leave this empty to use the default value of 10s.',default='10s'"`
}

// FlagsDebuginfo contains flags to configure debuginfo.
type FlagsDebuginfo struct {
	Directories           []string      `kong:"help='Ordered list of local directories to search for debuginfo files.',default='/usr/lib/debug'"`
	TempDir               string        `kong:"help='The local directory path to store the interim debuginfo files.',default='/tmp'"`
	Strip                 bool          `kong:"help='Only upload information needed for symbolization. If false the exact binary the agent sees will be uploaded unmodified.',default='true'"`
	UploadMaxParallel     int           `kong:"help='The maximum number of debuginfo upload requests to make in parallel.',default='25'"`
	UploadTimeoutDuration time.Duration `kong:"help='The timeout duration to cancel upload requests.',default='2m'"`
	UploadCacheDuration   time.Duration `kong:"help='The duration to cache debuginfo upload responses for.',default='5m'"`
	DisableCaching        bool          `kong:"help='Disable caching of debuginfo.',default='false'"`
}

// FlagsSymbolizer contains flags to configure symbolization.
type FlagsSymbolizer struct {
	JITDisable bool `kong:"help='Disable JIT symbolization.'"`
}

// FlagsDWARFUnwinding contains flags to configure DWARF unwinding.
type FlagsDWARFUnwinding struct {
	Disable bool `kong:"help='Do not unwind using .eh_frame information.'"`
}

// FlagsHidden contains hidden flags. Hidden debug flags (only for debugging).
type FlagsHidden struct {
	DebugProcessNames       []string `kong:"help='Only attach profilers to specified processes. comm name will be used to match the given matchers. Accepts Go regex syntax (https://pkg.go.dev/regexp/syntax).',hidden=''"`
	DebugNormalizeAddresses bool     `kong:"help='Normalize sampled addresses.',default='true',hidden=''"`
}

var _ Profiler = &profiler.NoopProfiler{}

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

	if runtime.GOARCH == "arm64" {
		level.Error(logger).Log("msg", "ARM64 support is currently in progress. See https://github.com/parca-dev/parca-agent/discussions/1376")
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

	if _, err := maxprocs.Set(maxprocs.Logger(func(format string, a ...interface{}) {
		level.Info(logger).Log("msg", fmt.Sprintf(format, a...))
	})); err != nil {
		level.Warn(logger).Log("msg", "failed to set GOMAXPROCS automatically", "err", err)
	}

	if err := run(logger, reg, flags); err != nil {
		level.Error(logger).Log("err", err)
	}
}

func run(logger log.Logger, reg *prometheus.Registry, flags flags) error {
	var (
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

	isContainer, err := kconfig.IsInContainer()
	if err != nil {
		level.Warn(logger).Log("msg", "failed to check if running in container", "err", err)
	}

	if isContainer {
		level.Info(logger).Log(
			"msg", "running in a container, need to access the host kernel config.",
		)
	}

	if err := kconfig.CheckBPFEnabled(); err != nil {
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

		conn, err := grpcConn(reg, flags.RemoteStore)
		if err != nil {
			return err
		}
		defer conn.Close()

		profileStoreClient = profilestorepb.NewProfileStoreServiceClient(conn)
		if !flags.RemoteStore.DebuginfoUploadDisable {
			debuginfoClient = debuginfopb.NewDebuginfoServiceClient(conn)
		} else {
			level.Info(logger).Log("msg", "debug information collection is disabled")
		}
	}

	var (
		ctx = context.Background()

		g                   okrun.Group
		batchWriteClient    = agent.NewBatchWriteClient(logger, reg, profileStoreClient, flags.RemoteStore.BatchWriteInterval, flags.Hidden.DebugNormalizeAddresses)
		localStorageEnabled = flags.LocalStore.Directory != ""
		profileListener     = agent.NewMatchingProfileListener(logger, batchWriteClient)
		profileWriter       profiler.ProfileWriter
	)

	if localStorageEnabled {
		profileWriter = profiler.NewFileProfileWriter(flags.LocalStore.Directory)
		level.Info(logger).Log("msg", "local profile storage is enabled", "dir", flags.LocalStore.Directory)
	} else {
		// TODO(kakkoyun): Writer can handle normalization by the help address normalizer.
		profileWriter = profiler.NewRemoteProfileWriter(logger, profileListener, flags.Hidden.DebugNormalizeAddresses)

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
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
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

	curr, max, err := rlimit.Files()
	if err != nil {
		return fmt.Errorf("failed to get rlimit NOFILE: %w", err)
	}
	level.Info(logger).Log("msg", "rlimit", "cur", curr, "max", max)

	ofp := objectfile.NewPool(logger, reg, curr) // Probably we need a little less than this.
	defer ofp.Close()                            // Will make sure all the files are closed.

	labelsManager := labels.NewManager(
		logger,
		reg,
		// All the metadata providers work best-effort.
		[]metadata.Provider{
			discoveryMetadata,
			metadata.Target(flags.Node, flags.Metadata.ExternalLabels),
			metadata.Compiler(logger, reg, ofp),
			metadata.Process(pfs),
			metadata.JavaProcess(logger),
			metadata.System(),
			metadata.PodHosts(),
		},
		cfg.RelabelConfigs,
		flags.Metadata.DisableCaching,
		flags.Profiling.Duration, // Cache durations are calculated from profiling duration.
	)

	vdsoCache, err := vdso.NewCache(ofp)
	if err != nil {
		level.Error(logger).Log("msg", "failed to initialize vdso cache", "err", err)
	}

	var dbginfo process.DebuginfoManager
	if !flags.RemoteStore.DebuginfoUploadDisable {
		dbginfo = debuginfo.New(
			log.With(logger, "component", "debuginfo"),
			reg,
			ofp,
			debuginfoClient,
			flags.Debuginfo.UploadMaxParallel,
			flags.Debuginfo.UploadTimeoutDuration,
			flags.Debuginfo.DisableCaching,
			flags.Debuginfo.UploadCacheDuration,
			flags.Debuginfo.Directories,
			flags.Debuginfo.Strip,
			flags.Debuginfo.TempDir,
		)
		defer dbginfo.Close()
	} else {
		dbginfo = debuginfo.NoopDebuginfoManager{}
	}

	profilers := []Profiler{
		cpu.NewCPUProfiler(
			logger,
			reg,
			process.NewInfoManager(
				logger,
				reg,
				process.NewMapManager(pfs, ofp),
				dbginfo,
				labelsManager,
				flags.Profiling.Duration,
			),
			address.NewNormalizer(logger, reg, flags.Hidden.DebugNormalizeAddresses),
			symbol.NewSymbolizer(
				log.With(logger, "component", "symbolizer"),
				perf.NewCache(logger),
				ksym.NewKsym(logger, reg, flags.Debuginfo.TempDir),
				vdsoCache,
				flags.Symbolizer.JITDisable,
			),
			profileWriter,
			flags.Profiling.Duration,
			flags.Profiling.CPUSamplingFrequency,
			flags.MemlockRlimit,
			flags.Hidden.DebugProcessNames,
			flags.DWARFUnwinding.Disable,
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
				defer level.Debug(logger).Log("msg", "stopped", "err", err, "profiler", p.Name())

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

func grpcConn(reg prometheus.Registerer, flags FlagsRemoteStore) (*grpc.ClientConn, error) {
	met := grpc_prometheus.NewClientMetrics()
	met.EnableClientHandlingTimeHistogram()
	reg.MustRegister(met)

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(parcadebuginfo.MaxMsgSize),
			grpc.MaxCallRecvMsgSize(parcadebuginfo.MaxMsgSize),
		),
		grpc.WithUnaryInterceptor(
			met.UnaryClientInterceptor(),
		),
		grpc.WithStreamInterceptor(
			met.StreamClientInterceptor(),
		),
	}
	if flags.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		config := &tls.Config{
			//nolint:gosec
			InsecureSkipVerify: flags.InsecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}

	if flags.BearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    flags.BearerToken,
			insecure: flags.Insecure,
		}))
	}

	if flags.BearerTokenFile != "" {
		b, err := os.ReadFile(flags.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token from file: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    strings.TrimSpace(string(b)),
			insecure: flags.Insecure,
		}))
	}

	return grpc.Dial(flags.Address, opts...)
}

type perRequestBearerToken struct {
	token    string
	insecure bool
}

func (t *perRequestBearerToken) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t *perRequestBearerToken) RequireTransportSecurity() bool {
	return !t.insecure
}
