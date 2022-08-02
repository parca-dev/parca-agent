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

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/go-kit/log/level"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/oklog/run"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/buildinfo"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/objectfile"
	"github.com/parca-dev/parca-agent/pkg/profiler"
	"github.com/parca-dev/parca-agent/pkg/template"
)

var (
	version string
	commit  string
	date    string
	goArch  string
)

type flags struct {
	LogLevel           string            `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`
	HTTPAddress        string            `kong:"help='Address to bind HTTP server to.',default=':7071'"`
	Node               string            `kong:"required,help='Name node the process is running on. If on Kubernetes, this must match the Kubernetes node name.'"`
	ExternalLabel      map[string]string `kong:"help='Label(s) to attach to all profiles.'"`
	StoreAddress       string            `kong:"help='gRPC address to send profiles and symbols to.'"`
	BearerToken        string            `kong:"help='Bearer token to authenticate with store.'"`
	BearerTokenFile    string            `kong:"help='File to read bearer token from to authenticate with store.'"`
	Insecure           bool              `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
	BatchWriteInterval time.Duration     `kong:"help='Interval between batcher client writes. Leave this empty to use the default value of 10s',default='10s'"`
	InsecureSkipVerify bool              `kong:"help='Skip TLS certificate verification.'"`
	SamplingRatio      float64           `kong:"help='Sampling ratio to control how many of the discovered targets to profile. Defaults to 1.0, which is all.',default='1.0'"`
	Kubernetes         bool              `kong:"help='Discover containers running on this node to profile automatically.',default='true'"`
	PodLabelSelector   string            `kong:"help='Label selector to control which Kubernetes Pods to select.'"`
	// TempDir is deprecated and will be eventually removed.
	TempDir           string        `kong:"help='(Deprecated) Temporary directory path to use for processing object files.',default=''"`
	SocketPath        string        `kong:"help='The filesystem path to the container runtimes socket. Leave this empty to use the defaults.'"`
	ProfilingDuration time.Duration `kong:"help='The agent profiling duration to use. Leave this empty to use the defaults.',default='10s'"`
	DebugInfoDisable  bool          `kong:"help='Disable debuginfo collection.',default='false'"`
}

func externalLabels(flagExternalLabels map[string]string, flagNode string) model.LabelSet {
	if flagExternalLabels == nil {
		flagExternalLabels = map[string]string{}
	}
	flagExternalLabels["node"] = flagNode

	externalLabels := model.LabelSet{"node": model.LabelValue(flagNode)}
	for k, v := range flagExternalLabels {
		externalLabels[model.LabelName(k)] = model.LabelValue(v)
	}
	return externalLabels
}

func main() {
	flags := flags{}
	kong.Parse(&flags)

	logger := logger.NewLogger(flags.LogLevel, logger.LogFormatLogfmt, "")

	// Fetch build info such as the git revision we are based off
	buildInfo, err := buildinfo.FetchBuildInfo()
	if err == nil {
		if commit == "" {
			commit = buildInfo.VcsRevision
		}
		if date == "" {
			date = buildInfo.VcsTime
		}
		if goArch == "" {
			goArch = buildInfo.GoArch
		}
	} else {
		level.Error(logger).Log("err", err)
	}

	node := flags.Node
	logger.Log("msg", "starting...", "node", node, "store", flags.StoreAddress)
	level.Debug(logger).Log("msg", "parca-agent initialized",
		"version", version,
		"commit", commit,
		"date", date,
		"config", fmt.Sprint(flags),
		"arch", goArch,
	)

	if flags.TempDir != "" {
		level.Warn(logger).Log("msg", "--temp-dir is deprecated and will be removed in a future release.")
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewBuildInfoCollector(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	profileStoreClient := agent.NewNoopProfileStoreClient()
	debugInfoClient := debuginfo.NewNoopClient()

	if len(flags.StoreAddress) > 0 {
		conn, err := grpcConn(reg, flags)
		defer conn.Close()

		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		// Initialize actual clients with the connection.
		profileStoreClient = profilestorepb.NewProfileStoreServiceClient(conn)
		if !flags.DebugInfoDisable {
			level.Info(logger).Log("msg", "debug information collection is enabled")
			debugInfoClient = parcadebuginfo.NewDebugInfoClient(conn)
		}
	}

	var (
		configs          discovery.Configs
		batchWriteClient = agent.NewBatchWriteClient(logger, profileStoreClient, flags.BatchWriteInterval)
		profileListener  = agent.NewProfileListener(logger, batchWriteClient)
	)

	if flags.Kubernetes {
		configs = append(configs, discovery.NewPodConfig(
			flags.PodLabelSelector,
			flags.SocketPath,
			flags.Node,
		))
	}

	pp := profiler.NewProfilerPool(
		logger,
		reg,
		ksym.NewKsymCache(logger),
		objectfile.NewCache(5),
		profileListener,
		debugInfoClient,
		flags.ProfilingDuration,
		externalLabels(flags.ExternalLabel, flags.Node),
		flags.SamplingRatio,
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			profilers := pp.Profilers()
			statusPage := template.StatusPage{}

			for name, profiler := range profilers {
				statusPage.ActiveProfilers = append(statusPage.ActiveProfilers, template.ActiveProfiler{
					Name:           name,
					Interval:       flags.ProfilingDuration,
					NextStartedAgo: time.Since(profiler.NextProfileStartedAt()),
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

	ctx := context.Background()
	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting batch write client")
			return batchWriteClient.Run(ctx)
		}, func(error) {
			cancel()
		})
	}

	var m *discovery.Manager
	// Run group for discovery manager
	{
		ctx, cancel := context.WithCancel(ctx)
		reg := prometheus.NewRegistry()
		m = discovery.NewManager(logger, reg)
		var err error

		if flags.Kubernetes {
			err = m.ApplyConfig(ctx, map[string]discovery.Configs{"pod": configs})

			if err != nil {
				level.Error(logger).Log("err", err)
				os.Exit(1)
			}
		}

		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting discovery manager")
			return m.Run(ctx)
		}, func(error) {
			cancel()
		})
	}

	// Add profiler.
	profiler := pp.AddProfiler(ctx, profiler.NewCPUProfiler, func() map[int]model.LabelSet {
		return m.ProcessLabels()
	})

	// Run group for profiler.
	{
		g.Add(func() error {
			return profiler.Run(ctx)
		}, func(err error) {
			profiler.Stop()
			level.Error(logger).Log("msg", "profiler ended with", "error", err, "profilerName", profiler.Name())
		})
	}

	// Run group for http server
	{
		ln, err := net.Listen("tcp", flags.HTTPAddress)
		if err != nil {
			level.Error(logger).Log("err", err)
			return
		}
		g.Add(func() error {
			return http.Serve(ln, mux)
		}, func(error) {
			ln.Close()
		})
	}

	g.Add(run.SignalHandler(ctx, os.Interrupt, os.Kill))
	if err := g.Run(); err != nil {
		level.Error(logger).Log("err", err)
	}
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
		b, err := ioutil.ReadFile(flags.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token from file: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    strings.TrimSpace(string(b)),
			insecure: flags.Insecure,
		}))
	}

	return grpc.Dial(flags.StoreAddress, opts...)
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
