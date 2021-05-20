// Copyright 2021 Polar Signals Inc.
//
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
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/polarsignals/polarsignals-agent/ksym"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type flags struct {
	LogLevel    string `enum:"error,warn,info,debug" help:"Log level." default:"info"`
	HttpAddress string `help:"Address to bind HTTP server to." default:":8080"`
	Node        string `required help:"Name of the Kubernetes node the process is running on."`
}

func main() {
	flags := flags{}
	kong.Parse(&flags)

	node := flags.Node
	logger := NewLogger(flags.LogLevel, LogFormatLogfmt, "")
	logger.Log("msg", "starting...", "node", node)
	mux := http.NewServeMux()
	reg := prometheus.NewRegistry()
	ctx := context.Background()
	var g run.Group

	ksymCache := ksym.NewKsymCache()
	m, err := NewPodManager(logger, node, ksymCache)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

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
			activeProfilers := m.ActiveProfilers()
			fmt.Fprint(w, "<p><b>Active Container Profilers</b></p><br/>\n")
			sort.Strings(activeProfilers)
			for _, activeProfiler := range activeProfilers {
				fmt.Fprintf(w, "<a href='/active-profilers/%s?debug=1'>%s</a><br/>\n", activeProfiler, activeProfiler)
			}

			fmt.Fprint(w, "<p><b>Prometheus Metrics</b></p><br/>\n")
			fmt.Fprint(w, "<a href='/metrics'>/metrics</a><br/>\n")

			fmt.Fprint(w, "<p><b>Own Golang Profiles</b></p><br/>\n")
			fmt.Fprint(w, "<a href='/debug/pprof/'>/debug/pprof</a><br/>\n")

			return
		}
		if strings.HasPrefix(r.URL.Path, "/active-profilers") {
			path := strings.TrimPrefix(r.URL.Path, "/active-profilers/")
			parts := strings.Split(path, "/")
			if len(parts) != 3 {
				http.Error(w, "incorrect URL path, must be /active-profilers/namespace-name/pod-name/container-name", http.StatusBadRequest)
				return
			}

			namespace := parts[0]
			pod := parts[1]
			container := parts[2]

			profile := m.LastProfileFrom(namespace, pod, container)
			if profile == nil {
				http.NotFound(w, r)
				return
			}

			v := r.URL.Query().Get("debug")
			if v == "1" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprintf(w, "<p><a href='/active-profilers/%s/%s/%s'>Download Pprof</a></p>\n", namespace, pod, container)
				fmt.Fprint(w, "<code><pre>\n")
				fmt.Fprint(w, profile.String())
				fmt.Fprint(w, "\n</pre></code>")
				return
			}

			w.Header().Set("Content-Type", "application/vnd.google.protobuf+gzip")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%s-%s-%s.pb.gz", namespace, pod, container))
			err := profile.Write(w)
			if err != nil {
				level.Error(m.logger).Log("msg", "failed to write profile", "err", err)
			}
			return
		}
		http.NotFound(w, r)
	})

	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			return m.Run(ctx)
		}, func(error) {
			cancel()
		})
	}

	{
		ln, _ := net.Listen("tcp", flags.HttpAddress)
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
