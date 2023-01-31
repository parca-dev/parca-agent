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

package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	systemd "github.com/coreos/go-systemd/v22/dbus"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/namespace"
)

type SystemdConfig struct{}

type SystemdDiscoverer struct {
	logger log.Logger
}

func (c *SystemdConfig) Name() string {
	return "systemd"
}

func NewSystemdConfig() *SystemdConfig {
	return &SystemdConfig{}
}

func (c *SystemdConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	return &SystemdDiscoverer{
		logger: d.Logger,
	}, nil
}

func (c *SystemdDiscoverer) Run(ctx context.Context, up chan<- []*Group) error {
	conn, err := systemd.NewWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to systemd D-Bus API, %w", err)
	}
	defer conn.Close()

	isSubStateChanged := func(u1, u2 *systemd.UnitStatus) bool {
		return u1.SubState != u2.SubState
	}

	isNotService := func(name string) bool {
		return !strings.HasSuffix(name, ".service")
	}

	updateCh, errCh := conn.SubscribeUnitsCustom(5*time.Second, 0, isSubStateChanged, isNotService)

	for {
		select {
		case update := <-updateCh:
			var groups []*Group

			for unit, status := range update {
				if status == nil || status.SubState != "running" {
					groups = append(groups, &Group{Source: unit})
					continue
				}

				mainPIDProperty, err := conn.GetServicePropertyContext(ctx, unit, "MainPID")
				if err != nil {
					level.Warn(c.logger).Log("msg", "failed to get MainPID property for service", "err", err, "unit", unit)
					continue
				}

				pid, ok := mainPIDProperty.Value.Value().(uint32)
				if !ok {
					level.Warn(c.logger).Log("msg", "failed to assert type of PID", "unit", unit)
					continue
				}

				adj, err := namespace.PIDNamespaceAdjacentPIDs(int(pid))
				if err != nil {
					level.Warn(c.logger).Log("msg", "failed to find PIDs that share the same namespace", "err", err, "unit", unit)
					continue
				}
				groups = append(groups, &Group{
					Targets: []model.LabelSet{{}},
					Labels: model.LabelSet{
						model.LabelName("systemd_unit"): model.LabelValue(unit),
					},
					Source: unit,
					PIDs:   append(adj, int(pid)),
				})
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case up <- groups:
			}
		case err := <-errCh:
			level.Warn(c.logger).Log("msg", "received error from systemd D-Bus API", "err", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
