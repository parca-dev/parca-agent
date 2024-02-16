// Copyright 2023-2024 The Parca Authors
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

package analytics

import (
	"context"
	"math/rand"
	"strconv"
	"time"

	prometheuspb "buf.build/gen/go/prometheus/prometheus/protocolbuffers/go"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	prometheusclientpb "github.com/prometheus/client_model/go"
	"github.com/zcalusic/sysinfo"
)

type AnalyticsSender struct {
	logger log.Logger

	client *Client

	machineID   string
	arch        string
	cpuCores    float64
	version     string
	si          sysinfo.SysInfo
	reg         *prometheus.Registry
	isContainer string
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	//nolint:gosec
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func NewSender(logger log.Logger, client *Client, arch string, cpuCores int, version string, si sysinfo.SysInfo, reg *prometheus.Registry, isContainer bool) *AnalyticsSender {
	return &AnalyticsSender{
		logger:      logger,
		client:      client,
		machineID:   randSeq(20),
		arch:        arch,
		cpuCores:    float64(cpuCores),
		version:     version,
		si:          si,
		reg:         reg,
		isContainer: strconv.FormatBool(isContainer),
	}
}

func (s *AnalyticsSender) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UnixMilli()
			wreq := &prometheuspb.WriteRequest{
				Timeseries: []*prometheuspb.TimeSeries{{
					Labels: []*prometheuspb.Label{{
						Name:  "__name__",
						Value: "parca_agent_info",
					}, {
						Name:  "machine_id",
						Value: s.machineID,
					}, {
						Name:  "arch",
						Value: s.arch,
					}, {
						Name:  "version",
						Value: s.version,
					}, {
						Name:  "kernel_version",
						Value: s.si.Kernel.Version,
					}, {
						Name:  "kernel_osrelease",
						Value: s.si.Kernel.Release,
					}, {
						Name:  "os_name",
						Value: s.si.OS.Name,
					}, {
						Name:  "os_vendor",
						Value: s.si.OS.Vendor,
					}, {
						Name:  "os_version",
						Value: s.si.OS.Version,
					}, {
						Name:  "os_release",
						Value: s.si.OS.Release,
					}, {
						Name:  "is_container",
						Value: s.isContainer,
					}},
					Samples: []*prometheuspb.Sample{{
						Value:     1,
						Timestamp: now,
					}},
				}, {
					Labels: []*prometheuspb.Label{{
						Name:  "__name__",
						Value: "parca_agent_cpu_cores",
					}, {
						Name:  "machine_id",
						Value: s.machineID,
					}},
					Samples: []*prometheuspb.Sample{{
						Value:     s.cpuCores,
						Timestamp: now,
					}},
				}},
			}

			// We now gather some interesting metrics from the registry and add them to the write request.
			metrics, err := s.reg.Gather()
			if err == nil { // If we fail to gather metrics, we just skip them.
				for _, metric := range metrics {
					switch metric.GetName() {
					case "parca_agent_bpf_program_enter_total",
						"parca_agent_bpf_program_miss_filter_total",
						"parca_agent_bpf_program_miss_kthreads_total",
						"parca_agent_bpf_program_miss_zero_pid_total",
						"parca_agent_bpf_program_runs_total":
						addCounterVec(wreq, metric.GetName(), s.machineID, now, metric.GetMetric())
					}
				}
			}
			if err := s.client.Send(ctx, wreq); err != nil {
				level.Debug(s.logger).Log("msg", "failed to send analytics", "err", err)
			}
		}
	}
}

func addCounterVec(wreq *prometheuspb.WriteRequest, name, machineID string, now int64, metric []*prometheusclientpb.Metric) {
	for _, m := range metric {
		labels := make([]*prometheuspb.Label, 0, len(m.GetLabel())+2)
		labels = append(labels, &prometheuspb.Label{Name: "__name__", Value: name})
		labels = append(labels, &prometheuspb.Label{Name: "machine_id", Value: machineID})
		for _, pair := range m.GetLabel() {
			labels = append(labels, &prometheuspb.Label{
				Name:  pair.GetName(),
				Value: pair.GetValue(),
			})
		}
		wreq.Timeseries = append(wreq.GetTimeseries(), &prometheuspb.TimeSeries{
			Labels: labels,
			Samples: []*prometheuspb.Sample{{
				Value:     m.GetCounter().GetValue(),
				Timestamp: now,
			}},
		})
	}
}
