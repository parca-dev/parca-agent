// Copyright 2021 The Parca Authors
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

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
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
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/parca-dev/parca-agent/pkg/agent"
	"github.com/parca-dev/parca-agent/pkg/debuginfo"
	"github.com/parca-dev/parca-agent/pkg/discovery"
	"github.com/parca-dev/parca-agent/pkg/ksym"
	"github.com/parca-dev/parca-agent/pkg/logger"
	"github.com/parca-dev/parca-agent/pkg/target"
	"github.com/parca-dev/parca-agent/pkg/template"
)

var (
	version string
	commit  string
	date    string
	builtBy string
)

type flags struct {
	LogLevel           string            `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`
	HttpAddress        string            `kong:"help='Address to bind HTTP server to.',default=':7071'"`
	Node               string            `kong:"required,help='Name node the process is running on. If on Kubernetes, this must match the Kubernetes node name.'"`
	ExternalLabel      map[string]string `kong:"help='Label(s) to attach to all profiles.'"`
	StoreAddress       string            `kong:"help='gRPC address to send profiles and symbols to.'"`
	BearerToken        string            `kong:"help='Bearer token to authenticate with store.'"`
	BearerTokenFile    string            `kong:"help='File to read bearer token from to authenticate with store.'"`
	Insecure           bool              `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
	InsecureSkipVerify bool              `kong:"help='Skip TLS certificate verification.'"`
	SamplingRatio      float64           `kong:"help='Sampling ratio to control how many of the discovered targets to profile. Defaults to 1.0, which is all.',default='1.0'"`
	Kubernetes         bool              `kong:"help='Discover containers running on this node to profile automatically.',default='true'"`
	PodLabelSelector   string            `kong:"help='Label selector to control which Kubernetes Pods to select.'"`
	SystemdUnits       []string          `kong:"help='systemd units to profile on this node.'"`
	TempDir            string            `kong:"help='Temporary directory path to use for object files.',default='/tmp'"`
	SocketPath         string            `kong:"help='The filesystem path to the container runtimes socket. Leave this empty to use the defaults.'"`
	ProfilingDuration  time.Duration     `kong:"help='The agent profiling duration to use. Leave this empty to use the defaults.',default='10s'"`
	SystemdCgroupPath  string            `kong:"help='The cgroupfs path to a systemd slice.'"`
}

func getExternalLabels(flagExternalLabels map[string]string, flagNode string) model.LabelSet {
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

	node := flags.Node
	logger.Log("msg", "starting...", "node", node, "store", flags.StoreAddress)
	level.Debug(logger).Log("msg", "parca-agent initialized",
		"version", version,
		"commit", commit,
		"date", date,
		"builtBy", builtBy,
		"config", fmt.Sprint(flags),
	)

	mux := http.NewServeMux()
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewBuildInfoCollector(),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	var wc profilestorepb.ProfileStoreServiceClient = agent.NewNoopProfileStoreClient()
	var dc debuginfo.Client = debuginfo.NewNoopClient()

	if len(flags.StoreAddress) > 0 {
		conn, err := grpcConn(reg, flags)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		// Initialize actual clients with the connection.
		wc = profilestorepb.NewProfileStoreServiceClient(conn)
		dc = parcadebuginfo.NewDebugInfoClient(conn)
	}

	ksymCache := ksym.NewKsymCache(logger)

	var (
		configs  discovery.Configs
		bwc      = agent.NewBatchWriteClient(logger, wc)
		listener = agent.NewProfileListener(logger, bwc)
	)

	if flags.Kubernetes {
		configs = append(configs, discovery.NewPodConfig(
			flags.PodLabelSelector,
			flags.SocketPath,
			flags.Node,
		))
	}

	if len(flags.SystemdUnits) > 0 {
		configs = append(configs, discovery.NewSystemdConfig(
			flags.SystemdUnits,
			flags.SystemdCgroupPath,
		))
	}

	externalLabels := getExternalLabels(flags.ExternalLabel, flags.Node)
	tm := target.NewManager(logger, externalLabels, ksymCache, listener, dc, flags.ProfilingDuration, flags.TempDir)

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
						LastTakenAgo: time.Since(profiler.LastProfileTakenAt()),
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
				http.Error(w, "Unexpected error occurred while rendering status page: "+err.Error(), http.StatusInternalServerError)
			}

			return
		}

		if strings.HasPrefix(r.URL.Path, "/query") {
			ctx := r.Context()
			query := r.URL.Query().Get("query")
			matchers, err := parser.ParseMetricSelector(query)
			if err != nil {
				http.Error(w, `query incorrectly formatted, expecting selector in form of: {name1="value1",name2="value2"}`, http.StatusBadRequest)
				return
			}

			// We profile every 10 seconds so leaving 1s wiggle room. If after
			// 11s no profile has matched, then there is very likely no
			// profiler running that matches the label-set.
			ctx, cancel := context.WithTimeout(ctx, time.Second*11)
			defer cancel()

			profile, err := listener.NextMatchingProfile(ctx, matchers)
			if profile == nil || err == context.Canceled {
				http.Error(w, "No profile taken in the last 11 seconds that matches the requested label-matchers query. Profiles are taken every 10 seconds so either the profiler matching the label-set has stopped profiling, or the label-set was incorrect.", http.StatusNotFound)
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
					switch s {
					case unix.SIGCHLD:
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
			return bwc.Run(ctx)
		}, func(error) {
			cancel()
		})
	}

	var m *discovery.Manager
	// Run group for discovery manager
	{
		ctx, cancel := context.WithCancel(ctx)
		reg := prometheus.NewRegistry()
		m = discovery.NewManager(ctx, logger, reg)
		var err error
		if len(flags.SystemdUnits) > 0 {
			err = m.ApplyConfig(map[string]discovery.Configs{"systemd": configs})

			if err != nil {
				level.Error(logger).Log("err", err)
				os.Exit(1)
			}
		}

		if flags.Kubernetes {
			err = m.ApplyConfig(map[string]discovery.Configs{"pod": configs})

			if err != nil {
				level.Error(logger).Log("err", err)
				os.Exit(1)
			}
		}

		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting discovery manager")
			return m.Run()
		}, func(error) {
			cancel()
		})
	}

	// Run group for target manager
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "starting target manager")
			return tm.Run(ctx, m.SyncCh(), reg)
		}, func(error) {
			cancel()
		})
	}

	// Run group for http server
	{
		ln, err := net.Listen("tcp", flags.HttpAddress)
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
			token:    string(b),
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
