// Copyright 2022-2024 The Parca Authors
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
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"

	"github.com/parca-dev/parca-agent/pkg/discovery/systemd"
)

type SystemdConfig struct{}

func NewSystemdConfig() *SystemdConfig {
	return &SystemdConfig{}
}

func (c *SystemdConfig) Name() string {
	return "systemd"
}

func (c *SystemdConfig) NewDiscoverer(d DiscovererOptions) (Discoverer, error) {
	return &SystemdDiscoverer{
		logger: d.Logger,
	}, nil
}

type SystemdDiscoverer struct {
	logger log.Logger
	client *systemd.Client
	units  map[string]systemd.Unit
}

func (d *SystemdDiscoverer) Run(ctx context.Context, up chan<- []Group) error {
	var err error
	d.client, err = systemd.New()
	if err != nil {
		return fmt.Errorf("failed to connect to systemd D-Bus API, %w", err)
	}
	defer func() {
		if err := d.client.Close(); err != nil {
			level.Warn(d.logger).Log("msg", "failed to close systemd client", "err", err)
		}
	}()

	for {
		select {
		case <-time.After(5 * time.Second):
			update, err := d.unitsUpdate()
			if err != nil {
				level.Warn(d.logger).Log("msg", "failed to get units from systemd D-Bus API", "err", err)
				if err = d.client.Reset(); err != nil {
					return err
				}

				continue
			}
			if len(update) == 0 {
				continue
			}

			groups := make([]Group, 0, len(update))
			for unitName, unit := range update {
				if unit.Name == "" || unit.SubState != "running" {
					groups = append(groups, &SingleTargetGroup{source: unitName})
					continue
				}

				pid, err := d.client.MainPID(unitName)
				if err != nil {
					level.Warn(d.logger).Log("msg", "failed to get MainPID from systemd D-Bus API", "err", err, "unit", unitName)
					if err = d.client.Reset(); err != nil {
						return err
					}

					continue
				}

				groups = append(groups, &SingleTargetGroup{
					source: unitName,
					labels: model.LabelSet{
						model.LabelName("systemd_unit"): model.LabelValue(unitName),
					},
					Target: int(pid),
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

// unitsUpdate returns systemd units if there were any changes detected.
func (d *SystemdDiscoverer) unitsUpdate() (map[string]systemd.Unit, error) {
	recent := make(map[string]systemd.Unit)
	err := d.client.ListUnits(systemd.IsService, func(u *systemd.Unit) {
		// Must copy a unit,
		// otherwise it will be modified on the next function call.
		recent[u.Name] = *u
	})
	if err != nil {
		return nil, err
	}

	// Collect new and changed units.
	update := make(map[string]systemd.Unit)
	for unitName, unit := range recent {
		seenUnit, ok := d.units[unitName]
		// Is it a new unit or
		// the existing one but with an updated substate?
		if !ok || seenUnit.SubState != unit.SubState {
			update[unitName] = unit
		}

		delete(d.units, unitName)
	}

	// Indicate that units were deleted.
	for unitName := range d.units {
		update[unitName] = systemd.Unit{}
	}

	d.units = recent

	// No changes.
	if len(update) == 0 {
		return nil, nil //nolint:nilnil
	}

	return update, nil
}
