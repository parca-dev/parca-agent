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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/containerd/containerd/sys/reaper"
	"github.com/go-kit/log/level"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/oklog/run"
	profilestorepb "github.com/parca-dev/parca/gen/proto/go/parca/profilestore/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/buildinfo"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/target"
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
	Cgroups            []string          `kong:"help='Cgroups to profile on this node.'"`
	// SystemdUnits is deprecated and will be eventually removed, please use the Cgroups flag instead.
	SystemdUnits      []string      `kong:"help='[deprecated, use --cgroups instead] systemd units to profile on this node.'"`
	TempDir           string        `kong:"help='Temporary directory path to use for processing object files.',default='/tmp'"`
	SocketPath        string        `kong:"help='The filesystem path to the container runtimes socket. Leave this empty to use the defaults.'"`
	ProfilingDuration time.Duration `kong:"help='The agent profiling duration to use. Leave this empty to use the defaults.',default='10s'"`
	CgroupPath        string        `kong:"help='The cgroupfs path.'"`
	// SystemdCgroupPath is deprecated and will be eventually removed, please use the CgroupPath flag instead.
	SystemdCgroupPath string `kong:"help='[deprecated, use --cgroup-path] The cgroupfs path to a systemd slice.'"`
	DebugInfoDisable  bool   `kong:"help='Disable debuginfo collection.',default='false'"`
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

	mux := http.NewServeMux()
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
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		// Initialize actual clients with the connection.
		profileStoreClient = profilestorepb.NewProfileStoreServiceClient(conn)
		if !flags.DebugInfoDisable {
			level.Info(logger).Log("msg", "debug information collection is enabled")
			debugInfoClient = parcadebuginfo.NewDebugInfoClient(conn)

			// Check if external dependencies for debug info extraction is there and healthy.
			for _, c := range [2]string{"objcopy", "eu-strip"} {
				if _, err := exec.LookPath(c); err != nil {
					if errors.Is(err, exec.ErrNotFound) {
						level.Error(logger).Log(
							"msg", "failed to find external dependency in the PATH; make sure it is installed and added to the PATH",
							"cmd", c,
						)
						os.Exit(1)
					}
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				if out, err := exec.CommandContext(ctx, c, "--help").CombinedOutput(); err != nil {
					cancel()
					level.Error(logger).Log(
						"msg", "failed to check whether external dependency is healthy",
						"err", err,
						"cmd", c,
						"output", string(out),
					)
					os.Exit(1)
				}
			}
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

	if len(flags.Cgroups) > 0 {
		configs = append(configs, discovery.NewSystemdConfig(
			flags.Cgroups,
			flags.CgroupPath,
		))
	}

	// TODO(javierhonduco): This is deprecated, remove few versions from now.
	if len(flags.SystemdUnits) > 0 {
		configs = append(configs, discovery.NewSystemdConfig(
			flags.SystemdUnits,
			flags.SystemdCgroupPath,
		))
	}

	tm := target.NewManager(
		logger, reg,
		profileListener, debugInfoClient,
		flags.ProfilingDuration,
		externalLabels(flags.ExternalLabel, flags.Node),
		flags.SamplingRatio,
		flags.TempDir,
	)

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
			activeProfilers := tm.ActiveProfilers()

			statusPage := template.StatusPage{}

			for _, profilerSet := range activeProfilers {
				for _, profiler := range profilerSet {
					profileType := ""
					labelSet := labels.Labels{}

					for name, value := range profiler.Labels() {
						if name == "__name__" {
							profileType = string(value)
						}
						if name != "__name__" {
							labelSet = append(labelSet,
								labels.Label{Name: string(name), Value: string(value)})
						}
					}

					sort.Sort(labelSet)

					q := url.Values{}
					q.Add("debug", "1")
					q.Add("query", labelSet.String())

					statusPage.ActiveProfilers = append(statusPage.ActiveProfilers, template.ActiveProfiler{
						Type:         profileType,
						Labels:       labelSet,
						LastTakenAgo: time.Since(profiler.LastSuccessfulProfileStartedAt()),
						Error:        profiler.LastError(),
						Link:         fmt.Sprintf("/query?%s", q.Encode()),
					})
				}
			}

			sort.Slice(statusPage.ActiveProfilers, func(j, k int) bool {
				a := statusPage.ActiveProfilers[j].Labels
				b := statusPage.ActiveProfilers[k].Labels

				l := len(a)
				if len(b) < l {
					l = len(b)
				}

				for i := 0; i < l; i++ {
					if a[i].Name != b[i].Name {
						return a[i].Name < b[i].Name
					}
					if a[i].Value != b[i].Value {
						return a[i].Value < b[i].Value
					}
				}
				// If all labels so far were in common, the set with fewer labels comes first.
				return len(a)-len(b) < 0
			})

			err := template.StatusPageTemplate.Execute(w, statusPage)
			if err != nil {
				http.Error(w,
					"Unexpected error occurred while rendering status page: "+err.Error(),
					http.StatusInternalServerError,
				)
			}

			return
		}

		if strings.HasPrefix(r.URL.Path, "/query") {
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

			// We profile every 10 seconds so leaving 1s wiggle room. If after
			// 11s no profile has matched, then there is very likely no
			// profiler running that matches the label-set.
			ctx, cancel := context.WithTimeout(ctx, time.Second*11)
			defer cancel()

			profile, err := profileListener.NextMatchingProfile(ctx, matchers)
			if profile == nil || errors.Is(err, context.Canceled) {
				http.Error(w,
					"No profile taken in the last 11 seconds that matches the requested label-matchers query. "+
						"Profiles are taken every 10 seconds so either the profiler matching the label-set has stopped profiling, "+
						"or the label-set was incorrect.",
					http.StatusNotFound,
				)
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

				fmt.Fprintf(w, "<p><a href='/query?%s'>Download Pprof</a></p>\n", q.Encode())
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

	ctx := context.Background()
	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			signals := make(chan os.Signal, 32)
			signal.Notify(signals, unix.SIGCHLD)
			// set the shim as the subreaper for all orphaned processes created by the container
			if err := reaper.SetSubreaper(1); err != nil {
				return err
			}

			for {
				select {
				case <-ctx.Done():
					if err := reaper.Reap(); err != nil {
						return err
					}
					return nil
				case s := <-signals:
					if s == unix.SIGCHLD {
						if err := reaper.Reap(); err != nil {
							return err
						}
					}
				}
			}
		}, func(error) {
			cancel()
		})
	}

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
		if len(flags.Cgroups) > 0 || len(flags.SystemdUnits) > 0 {
			err = m.ApplyConfig(ctx, map[string]discovery.Configs{"systemd": configs})

			if err != nil {
				level.Error(logger).Log("err", err)
				os.Exit(1)
			}
		}

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

	// Run group for target manager
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting target manager")
			return tm.Run(ctx, m.SyncCh())
		}, func(error) {
			cancel()
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
		grpc.WithUnaryInterceptor(
			met.UnaryClientInterceptor(),
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
