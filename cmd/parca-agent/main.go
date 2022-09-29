// Copyright 2022 The Parca Authors
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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	runtimepprof "runtime/pprof"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/common-nighthawk/go-figure"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	okrun "github.com/oklog/run"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/buildinfo"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/kconfig"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/metadata"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/perf"
	"github.com/parca-dev/parca-agent/pkg/process"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/profiler/cpu"
	"github.com/parca-dev/parca-agent/pkg/symbol"
	"github.com/parca-dev/parca-agent/pkg/template"
)

var (
	version string
	commit  string
	date    string
	goArch  string
)

type flags struct {
	LogLevel    string `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`
	HTTPAddress string `kong:"help='Address to bind HTTP server to.',default=':7071'"`

	Node string `kong:"required,help='The name of the node that the process is running on. If on Kubernetes, this must match the Kubernetes node name.'"`

	// Profiler configuration:
	ProfilingDuration time.Duration `kong:"help='The agent profiling duration to use. Leave this empty to use the defaults.',default='10s'"`

	// Metadata provider configuration:
	MetadataExternalLabels             map[string]string `kong:"help='Label(s) to attach to all profiles.'"`
	MetadataContainerRuntimeSocketPath string            `kong:"help='The filesystem path to the container runtimes socket. Leave this empty to use the defaults.'"`

	// Storage configuration:
	LocalStoreDirectory string `kong:"help='The local directory to store the profiling data.',default='./tmp/profiles'"`

	RemoteStoreAddress                string        `kong:"help='gRPC address to send profiles and symbols to.'"`
	RemoteStoreBearerToken            string        `kong:"help='Bearer token to authenticate with store.'"`
	RemoteStoreBearerTokenFile        string        `kong:"help='File to read bearer token from to authenticate with store.'"`
	RemoteStoreInsecure               bool          `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
	RemoteStoreInsecureSkipVerify     bool          `kong:"help='Skip TLS certificate verification.'"`
	RemoteStoreDebugInfoUploadDisable bool          `kong:"help='Disable debuginfo collection and upload.',default='false'"`
	RemoteStoreBatchWriteInterval     time.Duration `kong:"help='Interval between batch remote client writes. Leave this empty to use the default value of 10s.',default='10s'"`

	// Debug info configuration:
	DebugInfoDirectories []string `kong:"help='Ordered list of local directories to search for debug info files. Defaults to /usr/lib/debug.',default='/usr/lib/debug'"`
}

var _ Profiler = &profiler.NoopProfiler{}

type Profiler interface {
	Name() string
	Run(ctx context.Context) error

	LastProfileStartedAt() time.Time
	LastError() error
}

func main() {
	flags := flags{}
	kong.Parse(&flags)

	logger := logger.NewLogger(flags.LogLevel, logger.LogFormatLogfmt, "parca-agent")

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewBuildInfoCollector(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	intro := figure.NewColorFigure("Parca Agent ", "roman", "yellow", true)
	intro.Print()

	if err := run(logger, reg, flags); err != nil {
		level.Error(logger).Log("err", err)
	}
}

func run(logger log.Logger, reg *prometheus.Registry, flags flags) error {
	isContainer, err := kconfig.IsInContainer()
	if err != nil {
		level.Warn(logger).Log("msg", "failed to check if running in container", "err", err)
	}

	if isContainer {
		level.Info(logger).Log(
			"msg", "running in a container, need to access the host kernel config.",
		)
	}

	bpfEnabled, err := kconfig.IsBPFEnabled()
	if err != nil {
		level.Warn(logger).Log("msg", "failed to determine if eBPF is supported", "err", err)
	}
	if !bpfEnabled {
		return errors.New("host kernel does not support eBPF")
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

	var (
		ctx             = context.Background()
		debugInfoClient = debuginfo.NewNoopClient()

		g             okrun.Group
		profileWriter profiler.ProfileWriter
	)
	if len(flags.RemoteStoreAddress) > 0 {
		conn, err := grpcConn(reg, flags)
		if err != nil {
			return err
		}
		defer conn.Close()

		profileStoreClient := profilestorepb.NewProfileStoreServiceClient(conn)
		if !flags.RemoteStoreDebugInfoUploadDisable {
			debugInfoClient = parcadebuginfo.NewDebugInfoClient(conn)
		} else {
			level.Info(logger).Log("msg", "debug information collection is disabled")
		}

		batchWriteClient := agent.NewBatchWriteClient(logger, profileStoreClient, flags.RemoteStoreBatchWriteInterval)
		profileWriter = profiler.NewRemoteProfileWriter(agent.NewMatchingProfileListener(logger, batchWriteClient))
		{
			ctx, cancel := context.WithCancel(ctx)
			g.Add(func() (err error) {
				level.Debug(logger).Log("msg", "starting: batch write client")
				defer level.Debug(logger).Log("msg", "stopped: batch write client")

				runtimepprof.Do(ctx, runtimepprof.Labels("component", "remote_profile_writer"), func(ctx context.Context) {
					err = batchWriteClient.Run(ctx)
				})

				return
			}, func(error) {
				cancel()
			})
		}
	} else if flags.LocalStoreDirectory != "" {
		profileWriter = profiler.NewFileProfileWriter(flags.LocalStoreDirectory)
		level.Info(logger).Log("msg", "local profile storage is enabled", "dir", flags.LocalStoreDirectory)
	}

	if profileWriter == nil {
		return errors.New("no profile writer configured")
	}

	logger.Log("msg", "starting...", "node", flags.Node, "store", flags.RemoteStoreAddress)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	var m *discovery.Manager
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
		m = discovery.NewManager(logger, reg,
			discovery.WithProcessLabelCache(cache.New(
				cache.WithExpireAfterAccess(flags.RemoteStoreBatchWriteInterval*2),
			)),
		)
		if err := m.ApplyConfig(ctx, map[string]discovery.Configs{"all": configs}); err != nil {
			cancel()
			return err
		}

		g.Add(func() (err error) {
			level.Debug(logger).Log("msg", "starting: discovery manager")
			defer level.Debug(logger).Log("msg", "stopped: discovery manager")

			runtimepprof.Do(ctx, runtimepprof.Labels("component", "discovery_manager"), func(ctx context.Context) {
				err = m.Run(ctx)
			})

			return
		}, func(error) {
			cancel()
		})
	}

	profilers := []Profiler{
		cpu.NewCPUProfiler(
			logger,
			reg,
			symbol.NewSymbolizer(
				log.With(logger, "component", "symbolizer"),
				perf.NewCache(logger),
				ksym.NewKsymCache(logger, reg),
			),
			process.NewMappingFileCache(logger),
			objectfile.NewCache(20),
			profileWriter,
			debuginfo.New(
				log.With(logger, "component", "debuginfo"),
				reg,
				debugInfoClient,
				flags.DebugInfoDirectories,
			),
			// All the metadata providers work best-effort.
			[]profiler.MetadataProvider{
				metadata.ServiceDiscovery(m),
				metadata.Target(flags.Node, flags.MetadataExternalLabels),
				metadata.Cgroup(),
				metadata.Compiler(),
			},
			flags.ProfilingDuration,
		),
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			statusPage := template.StatusPage{}

			for _, profiler := range profilers {
				statusPage.ActiveProfilers = append(statusPage.ActiveProfilers, template.ActiveProfiler{
					Name:           profiler.Name(),
					Interval:       flags.ProfilingDuration,
					NextStartedAgo: time.Since(profiler.LastProfileStartedAt()),
					Error:          profiler.LastError(),
				})
			}
			err := template.StatusPageTemplate.Execute(w, statusPage)
			if err != nil {
				http.Error(w,
					"Unexpected error occurred while rendering status page: "+err.Error(),
					http.StatusInternalServerError,
				)
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
			g.Add(func() (err error) {
				level.Debug(logger).Log("msg", "starting: profiler", "name", p.Name())
				defer level.Debug(logger).Log("msg", "profiler: stopped", "err", err, "profiler", p.Name())

				runtimepprof.Do(ctx, runtimepprof.Labels("component", p.Name()), func(ctx context.Context) {
					err = p.Run(ctx)
				})

				return
			}, func(err error) {
				cancel()
			})
		}
	}

	// Run group for http server.
	{
		ln, err := net.Listen("tcp", flags.HTTPAddress)
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}
		g.Add(func() (err error) {
			level.Debug(logger).Log("msg", "starting: http server")
			defer level.Debug(logger).Log("msg", "stopped: http server")

			runtimepprof.Do(ctx, runtimepprof.Labels("component", "http_server"), func(_ context.Context) {
				err = http.Serve(ln, mux)
			})

			return
		}, func(error) {
			ln.Close()
		})
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
