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
	systemd2 "github.com/marselester/systemd"
	"github.com/prometheus/common/model"
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

				groups = append(groups, &Group{
					Targets: []model.LabelSet{{}},
					Labels: model.LabelSet{
						model.LabelName("systemd_unit"): model.LabelValue(unit),
					},
					Source:   unit,
					EntryPID: int(pid),
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

type Systemd2Config struct{}

func NewSystemd2Config() *Systemd2Config {
	return &Systemd2Config{}
}

func (c *Systemd2Config) Name() string {
	return "systemd2"
}

func (c *Systemd2Config) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	return &Systemd2Discoverer{
		logger: d.Logger,
		prev:   make(map[string]systemd2.Unit),
	}, nil
}

type Systemd2Discoverer struct {
	logger log.Logger
	prev   map[string]systemd2.Unit
}

func (d *Systemd2Discoverer) Run(ctx context.Context, up chan<- []*Group) error {
	c, err := systemd2.New()
	if err != nil {
		return fmt.Errorf("failed to connect to systemd D-Bus API, %w", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			level.Warn(d.logger).Log("msg", "failed to close systemd", "err", err)
		}
	}()

	for {
		select {
		case <-time.After(5 * time.Second):
			update, err := d.updatedUnits(c)
			if err != nil {
				level.Warn(d.logger).Log("msg", "failed to get units from systemd D-Bus API", "err", err)
				continue
			}
			if len(update) == 0 {
				continue
			}

			groups := make([]*Group, 0, len(update))
			for unitName, unit := range update {
				if unit.Name == "" || unit.SubState != "running" {
					groups = append(groups, &Group{Source: unitName})
					continue
				}

				pid, err := c.MainPID(unitName)
				if err != nil {
					level.Warn(d.logger).Log("msg", "failed to get MainPID from systemd D-Bus API", "err", err, "unit", unitName)
					continue
				}

				groups = append(groups, &Group{
					Targets: []model.LabelSet{{}},
					Labels: model.LabelSet{
						model.LabelName("systemd_unit"): model.LabelValue(unitName),
					},
					Source:   unitName,
					EntryPID: int(pid),
				})
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case up <- groups:
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// updatedUnits is like SubscribeUnitsCustom
// from github.com/coreos/go-systemd/v22/dbus,
// i.e., it returns systemd units if there were any changes detected.
func (d *Systemd2Discoverer) updatedUnits(c *systemd2.Client) (map[string]systemd2.Unit, error) {
	cur := make(map[string]systemd2.Unit)
	err := c.ListUnits(systemd2.IsService, func(u *systemd2.Unit) {
		// Must copy a unit,
		// otherwise it will be modified on the next function call.
		cur[u.Name] = *u
	})
	if err != nil {
		return nil, err
	}

	// Collect all new and changed units.
	changed := make(map[string]systemd2.Unit)
	for name, unit := range cur {
		prevUnit, ok := d.prev[name]
		// Is it a new unit or
		// the existing one but with an updated substate?
		if !ok || prevUnit.SubState != unit.SubState {
			changed[name] = unit
		}

		delete(d.prev, name)
	}

	// Add all deleted units.
	for name := range d.prev {
		changed[name] = systemd2.Unit{}
	}

	d.prev = cur

	// No changes.
	if len(changed) == 0 {
		return nil, nil //nolint:nilnil
	}

	return changed, nil
}
