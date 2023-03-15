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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/procfs"
	"github.com/prometheus/prometheus/promql/parser"
	"go.uber.org/automaxprocs/maxprocs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

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
)

type flags struct {
	LogLevel    string `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`
	HTTPAddress string `kong:"help='Address to bind HTTP server to.',default=':7071'"`

	Node          string `kong:"help='The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name.',default='${hostname}'"`
	ConfigPath    string `default:"" help:"Path to config file."`
	MemlockRlimit uint64 `default:"${default_memlock_rlimit}" help:"The value for the maximum number of bytes of memory that may be locked into RAM. It is used to ensure the agent can lock memory for eBPF maps. 0 means no limit."`

	// Profiler configuration:
	ProfilingDuration             time.Duration `kong:"help='The agent profiling duration to use. Leave this empty to use the defaults.',default='10s'"`
	ProfilingCPUSamplingFrequency uint64        `kong:"help='The frequency at which profiling data is collected, e.g., 19 samples per second.',default='${default_cpu_sampling_frequency}'"`

	// Metadata provider configuration:
	MetadataExternalLabels             map[string]string `kong:"help='Label(s) to attach to all profiles.'"`
	MetadataContainerRuntimeSocketPath string            `kong:"help='The filesystem path to the container runtimes socket. Leave this empty to use the defaults.'"`

	// Storage configuration:
	LocalStoreDirectory string `kong:"help='The local directory to store the profiling data.'"`

	RemoteStoreAddress                string        `kong:"help='gRPC address to send profiles and symbols to.'"`
	RemoteStoreBearerToken            string        `kong:"help='Bearer token to authenticate with store.'"`
	RemoteStoreBearerTokenFile        string        `kong:"help='File to read bearer token from to authenticate with store.'"`
	RemoteStoreInsecure               bool          `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
	RemoteStoreInsecureSkipVerify     bool          `kong:"help='Skip TLS certificate verification.'"`
	RemoteStoreDebuginfoUploadDisable bool          `kong:"help='Disable debuginfo collection and upload.',default='false'"`
	RemoteStoreBatchWriteInterval     time.Duration `kong:"help='Interval between batch remote client writes. Leave this empty to use the default value of 10s.',default='10s'"`

	// Debuginfo configuration:
	DebuginfoDirectories           []string      `kong:"help='Ordered list of local directories to search for debuginfo files. Defaults to /usr/lib/debug.',default='/usr/lib/debug'"`
	DebuginfoTempDir               string        `kong:"help='The local directory path to store the interim debuginfo files.',default='/tmp'"`
	DebuginfoStrip                 bool          `kong:"help='Only upload information needed for symbolization. If false the exact binary the agent sees will be uploaded unmodified.',default='true'"`
	DebuginfoUploadCacheDuration   time.Duration `kong:"help='The duration to cache debuginfo upload exists checks for.',default='5m'"`
	DebuginfoUploadTimeoutDuration time.Duration `kong:"help='The timeout duration to cancel upload requests.',default='2m'"`

	// Hidden debug flags (only for debugging):
	DebugProcessNames []string `kong:"help='Only attach profilers to specified processes. comm name will be used to match the given matchers. Accepts Go regex syntax (https://pkg.go.dev/regexp/syntax).',hidden=''"`

	// Native unwinding flags.
	DisableDWARFUnwinding    bool `kong:"help='Do not unwind using .eh_frame information.'"`
	DWARFUnwindingUsePolling bool `kong:"help='Poll procfs to generate the unwind information instead of generating them on demand.'"`
	VerboseBpfLogging        bool `kong:"help='Enable verbose BPF logging.'"`
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
	hostname, hostnameErr := os.Hostname()

	flags := flags{}
	kong.Parse(&flags, kong.Vars{
		"hostname":                       hostname,
		"default_memlock_rlimit":         "0", // No limit by default.
		"default_cpu_sampling_frequency": strconv.Itoa(defaultCPUSamplingFrequency),
	})

	logger := logger.NewLogger(flags.LogLevel, logger.LogFormatLogfmt, "parca-agent")

	if flags.Node == "" && hostnameErr != nil {
		level.Error(logger).Log("msg", "failed to get host name. Please set it with the --node flag", "err", hostnameErr)
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
		if flags.DisableDWARFUnwinding {
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

	if flags.ProfilingCPUSamplingFrequency <= 0 {
		level.Warn(logger).Log("msg", "cpu sampling frequency is too low. Setting it to the default value", "default", defaultCPUSamplingFrequency)
		flags.ProfilingCPUSamplingFrequency = defaultCPUSamplingFrequency
	} else if flags.ProfilingCPUSamplingFrequency > maxAdvicedCPUSamplingFrequency {
		level.Warn(logger).Log("msg", "cpu sampling frequency is too high, it can impact overall machine performance", "max", maxAdvicedCPUSamplingFrequency)
	}
	if flags.ProfilingCPUSamplingFrequency != defaultCPUSamplingFrequency {
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
		// TODO(kakkoyun): Add a more definitive test for the cases kconfig fails.
		// - https://github.com/libbpf/libbpf/blob/1714037104da56308ddb539ae0a362a9936121ff/src/libbpf.c#L4396-L4429
		level.Warn(logger).Log("msg", "failed to determine if eBPF is supported, host kernel might not support eBPF", "err", err)
	} else {
		level.Info(logger).Log("msg", "eBPF is supported and enabled by the host kernel")
	}

	// Fetch build info such as the git revision we are based off
	buildInfo, err := buildinfo.FetchBuildInfo()
	if err != nil {
		return fmt.Errorf("failed to fetch build info: %w", err)
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
	level.Debug(logger).Log("msg", "parca-agent initialized",
		"version", version,
		"commit", commit,
		"date", date,
		"config", fmt.Sprintf("%+v", flags),
		"arch", goArch,
	)

	profileStoreClient := agent.NewNoopProfileStoreClient()
	var debuginfoClient debuginfopb.DebuginfoServiceClient = debuginfo.NewNoopClient()

	if len(flags.RemoteStoreAddress) > 0 {
		conn, err := grpcConn(reg, flags)
		if err != nil {
			return err
		}
		defer conn.Close()

		profileStoreClient = profilestorepb.NewProfileStoreServiceClient(conn)
		if !flags.RemoteStoreDebuginfoUploadDisable {
			debuginfoClient = debuginfopb.NewDebuginfoServiceClient(conn)
		} else {
			level.Info(logger).Log("msg", "debug information collection is disabled")
		}
	}

	var (
		ctx = context.Background()

		g                   okrun.Group
		batchWriteClient    = agent.NewBatchWriteClient(logger, reg, profileStoreClient, flags.RemoteStoreBatchWriteInterval)
		localStorageEnabled = flags.LocalStoreDirectory != ""
		profileListener     = agent.NewMatchingProfileListener(logger, batchWriteClient)
		profileWriter       profiler.ProfileWriter
	)

	if localStorageEnabled {
		profileWriter = profiler.NewFileProfileWriter(flags.LocalStoreDirectory)
		level.Info(logger).Log("msg", "local profile storage is enabled", "dir", flags.LocalStoreDirectory)
	} else {
		profileWriter = profiler.NewRemoteProfileWriter(logger, profileListener)
		{
			ctx, cancel := context.WithCancel(ctx)
			g.Add(func() error {
				level.Debug(logger).Log("msg", "starting: batch write client")
				defer level.Debug(logger).Log("msg", "stopped: batch write client")

				var err error
				runtimepprof.Do(ctx, runtimepprof.Labels("component", "remote_profile_writer"), func(ctx context.Context) {
					err = batchWriteClient.Run(ctx)
				})

				return err
			}, func(error) {
				cancel()
			})
		}
	}

	logger.Log("msg", "starting...", "node", flags.Node, "store", flags.RemoteStoreAddress)

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

	var discoveryManager *discovery.Manager
	// Run group for discovery manager
	{
		ctx, cancel := context.WithCancel(ctx)
		configs := discovery.Configs{
			discovery.NewPodConfig(
				flags.Node,
				flags.MetadataContainerRuntimeSocketPath,
			),
			discovery.NewSystemdConfig(),
		}
		discoveryManager = discovery.NewManager(logger, reg)
		if err := discoveryManager.ApplyConfig(ctx, map[string]discovery.Configs{"all": configs}); err != nil {
			cancel()
			return err
		}

		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting: discovery manager")
			defer level.Debug(logger).Log("msg", "stopped: discovery manager")

			var err error
			runtimepprof.Do(ctx, runtimepprof.Labels("component", "discovery_manager"), func(ctx context.Context) {
				err = discoveryManager.Run(ctx)
			})

			return err
		}, func(error) {
			cancel()
		})
	}

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return fmt.Errorf("failed to open procfs: %w", err)
	}

	psTree := process.NewTree(logger, pfs, flags.ProfilingDuration)
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			return psTree.Run(ctx)
		}, func(error) {
			cancel()
		})
	}

	discoveryMetadata := metadata.ServiceDiscovery(logger, discoveryManager.SyncCh(), psTree)
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			return discoveryMetadata.Run(ctx)
		}, func(error) {
			cancel()
		})
	}

	labelsManager := labels.NewManager(
		logger,
		// All the metadata providers work best-effort.
		[]metadata.Provider{
			discoveryMetadata,
			metadata.Target(flags.Node, flags.MetadataExternalLabels),
			metadata.Compiler(),
			metadata.Process(pfs),
			metadata.JavaProcess(logger),
			metadata.System(),
			metadata.PodHosts(),
		},
		cfg.RelabelConfigs,
		flags.ProfilingDuration, // Cache durations are calculated from profiling duration.
	)

	vdsoCache, err := vdso.NewCache()
	if err != nil {
		level.Error(logger).Log("msg", "failed to initialize vdso cache", "err", err)
	}
	profilers := []Profiler{
		cpu.NewCPUProfiler(
			logger,
			reg,
			symbol.NewSymbolizer(
				log.With(logger, "component", "symbolizer"),
				perf.NewCache(logger),
				ksym.NewKsymCache(logger, reg),
				vdsoCache,
			),
			process.NewMappingFileCache(logger),
			objectfile.NewCache(20, flags.ProfilingDuration),
			profileWriter,
			debuginfo.New(
				log.With(logger, "component", "debuginfo"),
				reg,
				debuginfoClient,
				flags.DebuginfoUploadTimeoutDuration,
				flags.DebuginfoUploadCacheDuration,
				flags.DebuginfoDirectories,
				flags.DebuginfoStrip,
				flags.DebuginfoTempDir,
			),
			labelsManager,
			flags.ProfilingDuration,
			flags.ProfilingCPUSamplingFrequency,
			flags.MemlockRlimit,
			flags.DebugProcessNames,
			flags.DisableDWARFUnwinding,
			flags.DWARFUnwindingUsePolling,
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
				ProfilingInterval:   flags.ProfilingDuration,
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
					lbls := labelsManager.Labels(prflr.Name(), uint64(pid))
					if lbls == nil {
						continue
					}

					err, active := processLastErrors[prflr.Name()][pid]

					switch {
					case err != nil:
						lastError = err
						profilingStatus = "errors"
					case active:
						profilingStatus = "active"
					default:
						profilingStatus = "inactive"
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
			ctx := r.Context()
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
			timeout := flags.ProfilingDuration + time.Second
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			profile, err := profileListener.NextMatchingProfile(ctx, matchers)
			if profile == nil || errors.Is(err, context.Canceled) {
				http.Error(w, fmt.Sprintf(
					"No profile taken in the last %s that matches the requested label-matchers query. "+
						"Profiles are taken every %s so either the profiler matching the label-set has stopped profiling, "+
						"or the label-set was incorrect.",
					timeout, flags.ProfilingDuration,
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
					flags.ProfilingDuration,
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
			g.Add(func() error {
				level.Debug(logger).Log("msg", "starting: profiler", "name", p.Name())
				defer level.Debug(logger).Log("msg", "profiler: stopped", "err", err, "profiler", p.Name())

				var err error
				runtimepprof.Do(ctx, runtimepprof.Labels("component", p.Name()), func(ctx context.Context) {
					err = p.Run(ctx)
				})

				return err
			}, func(err error) {
				cancel()
			})
		}
	}

	// Run group for http server.
	{
		srv := &http.Server{
			Addr:         flags.HTTPAddress,
			Handler:      mux,
			ReadTimeout:  5 * time.Second, // TODO(kakkoyun): Make this configurable.
			WriteTimeout: time.Minute,     // TODO(kakkoyun): Make this configurable.
		}

		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting: http server")
			defer level.Debug(logger).Log("msg", "stopped: http server")

			var err error
			runtimepprof.Do(ctx, runtimepprof.Labels("component", "http_server"), func(_ context.Context) {
				err = srv.ListenAndServe()
			})

			return err
		}, func(error) {
			srv.Close()
		})
	}

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

		g.Add(
			func() error {
				level.Debug(logger).Log("msg", "starting: config file reloader")
				defer level.Debug(logger).Log("msg", "stopped: config file reloader")

				var err error
				runtimepprof.Do(ctx, runtimepprof.Labels("component", "config_file_reloader"), func(_ context.Context) {
					err = cfgReloader.Run(ctx)
				})

				return err
			},
			func(error) {
				cancel()
			},
		)
	}

	g.Add(okrun.SignalHandler(ctx, os.Interrupt, os.Kill))
	return g.Run()
}

func grpcConn(reg prometheus.Registerer, flags flags) (*grpc.ClientConn, error) {
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
	if flags.RemoteStoreInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		config := &tls.Config{
			//nolint:gosec
			InsecureSkipVerify: flags.RemoteStoreInsecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}

	if flags.RemoteStoreBearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    flags.RemoteStoreBearerToken,
			insecure: flags.RemoteStoreInsecure,
		}))
	}

	if flags.RemoteStoreBearerTokenFile != "" {
		b, err := os.ReadFile(flags.RemoteStoreBearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token from file: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    strings.TrimSpace(string(b)),
			insecure: flags.RemoteStoreInsecure,
		}))
	}

	return grpc.Dial(flags.RemoteStoreAddress, opts...)
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
