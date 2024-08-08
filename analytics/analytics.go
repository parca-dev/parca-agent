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

	prometheus "buf.build/gen/go/prometheus/prometheus/protocolbuffers/go"
	log "github.com/sirupsen/logrus"
	"github.com/zcalusic/sysinfo"
)

type AnalyticsSender struct {
	client *Client

	machineID   string
	arch        string
	cpuCores    float64
	version     string
	si          sysinfo.SysInfo
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

func NewSender(
	client *Client,
	arch string,
	cpuCores int,
	version string,
	si sysinfo.SysInfo,
	isContainer bool,
) *AnalyticsSender {
	return &AnalyticsSender{
		client:      client,
		machineID:   randSeq(20),
		arch:        arch,
		cpuCores:    float64(cpuCores),
		version:     version,
		si:          si,
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
			now := FromTime(time.Now())
			if err := s.client.Send(ctx, &prometheus.WriteRequest{
				Timeseries: []*prometheus.TimeSeries{{
					Labels: []*prometheus.Label{{
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
					Samples: []*prometheus.Sample{{
						Value:     1,
						Timestamp: now,
					}},
				}, {
					Labels: []*prometheus.Label{{
						Name:  "__name__",
						Value: "parca_agent_cpu_cores",
					}, {
						Name:  "machine_id",
						Value: s.machineID,
					}},
					Samples: []*prometheus.Sample{{
						Value:     s.cpuCores,
						Timestamp: now,
					}},
				}},
			}); err != nil {
				log.Debugf("failed to send analytics: %v", err)
			}
		}
	}
}

func FromTime(t time.Time) int64 {
	return t.Unix()*1000 + int64(t.Nanosecond())/int64(time.Millisecond)
}
