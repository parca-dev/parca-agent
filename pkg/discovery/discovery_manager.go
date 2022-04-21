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

package discovery

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/parca-dev/parca-agent/pkg/target"
)

type metrics struct {
	failedConfigs     prometheus.Gauge
	discoveredTargets *prometheus.GaugeVec
	receivedUpdates   prometheus.Counter
	delayedUpdates    prometheus.Counter
	sentUpdates       prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	var m metrics

	m.failedConfigs = promauto.With(reg).NewGauge(
		prometheus.GaugeOpts{
			Name: "parca_agent_sd_failed_configs",
			Help: "Current number of service discovery configurations that failed to load.",
		})
	m.discoveredTargets = promauto.With(reg).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "parca_agent_sd_discovered_targets",
			Help: "Current number of discovered targets.",
		},
		[]string{"config"})
	m.receivedUpdates = promauto.With(reg).NewCounter(
		prometheus.CounterOpts{
			Name: "parca_agent_sd_received_updates_total",
			Help: "Total number of update events received from the SD providers.",
		})
	m.delayedUpdates = promauto.With(reg).NewCounter(
		prometheus.CounterOpts{
			Name: "parca_agent_sd_updates_delayed_total",
			Help: "Total number of update events that couldn't be sent immediately.",
		})
	m.sentUpdates = promauto.With(reg).NewCounter(
		prometheus.CounterOpts{
			Name: "parca_agent_sd_updates_total",
			Help: "Total number of update events sent to the SD consumers.",
		})

	return &m
}

type poolKey struct {
	setName  string
	provider string
}

// provider holds a Discoverer instance, its configuration and its subscribers.
type provider struct {
	name   string
	d      Discoverer
	subs   []string
	config interface{}
}

// NewManager is the Discovery Manager constructor.
func NewManager(logger log.Logger, reg prometheus.Registerer, options ...func(*Manager)) *Manager {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	mgr := &Manager{
		logger:         logger,
		syncCh:         make(chan map[string][]*target.Group),
		Targets:        make(map[poolKey]map[string]*target.Group),
		discoverCancel: []context.CancelFunc{},
		metrics:        newMetrics(reg),
		updatert:       5 * time.Second,
		triggerSend:    make(chan struct{}, 1),
	}
	for _, option := range options {
		option(mgr)
	}
	return mgr
}

// Manager maintains a set of discovery providers and sends each update to a map channel.
// Targets are grouped by the target set name.
type Manager struct {
	logger log.Logger

	mtx            sync.RWMutex
	discoverCancel []context.CancelFunc

	metrics *metrics

	// Some Discoverers(eg. k8s) send only the updates for a given target group
	// so we use map[tg.Source]*Group to know which group to update.
	Targets map[poolKey]map[string]*target.Group
	// providers keeps track of SD providers.
	providers []*provider
	// The sync channel sends the updates as a map where the key is the job value from the scrape config.
	syncCh chan map[string][]*target.Group

	// How long to wait before sending updates to the channel. The variable
	// should only be modified in unit tests.
	updatert time.Duration

	// The triggerSend channel signals to the manager that new updates have been received from providers.
	triggerSend chan struct{}
}

// Run starts the background processing.
func (m *Manager) Run(ctx context.Context) error {
	go m.sender(ctx)
	for range ctx.Done() {
		m.cancelDiscoverers()
		return ctx.Err()
	}
	return nil
}

// SyncCh returns a read only channel used by all the clients to receive target updates.
func (m *Manager) SyncCh() <-chan map[string][]*target.Group {
	return m.syncCh
}

// ApplyConfig removes all running discovery providers and starts new ones using the provided config.
func (m *Manager) ApplyConfig(ctx context.Context, cfg map[string]Configs) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	for pk := range m.Targets {
		if _, ok := cfg[pk.setName]; !ok {
			m.metrics.discoveredTargets.DeleteLabelValues(pk.setName)
		}
	}
	m.cancelDiscoverers()
	m.Targets = make(map[poolKey]map[string]*target.Group)
	m.providers = nil
	m.discoverCancel = nil

	failedCount := 0
	for name, scfg := range cfg {
		failedCount += m.registerProviders(scfg, name)
		m.metrics.discoveredTargets.WithLabelValues(name).Set(0)
	}
	m.metrics.failedConfigs.Set(float64(failedCount))

	for _, prov := range m.providers {
		m.startProvider(ctx, prov)
	}

	return nil
}

// StartCustomProvider is used for sdtool. Only use this if you know what you're doing.
func (m *Manager) StartCustomProvider(ctx context.Context, name string, worker Discoverer) {
	p := &provider{
		name: name,
		d:    worker,
		subs: []string{name},
	}
	m.providers = append(m.providers, p)
	m.startProvider(ctx, p)
}

func (m *Manager) startProvider(ctx context.Context, p *provider) {
	level.Debug(m.logger).Log("msg", "starting provider", "provider", p.name, "subs", fmt.Sprintf("%v", p.subs))
	ctx, cancel := context.WithCancel(ctx)
	updates := make(chan []*target.Group)

	m.discoverCancel = append(m.discoverCancel, cancel)

	go func() {
		err := p.d.Run(ctx, updates)
		level.Debug(m.logger).Log("msg", "unable to start provider", "provider", p.name, "error", err)
	}()

	go m.updater(ctx, p, updates)
}

func (m *Manager) updater(ctx context.Context, p *provider, updates chan []*target.Group) {
	for {
		select {
		case <-ctx.Done():
			return
		case tgs, ok := <-updates:
			m.metrics.receivedUpdates.Inc()
			if !ok {
				level.Debug(m.logger).Log("msg", "discoverer channel closed", "provider", p.name)
				return
			}

			for _, s := range p.subs {
				m.updateGroup(poolKey{setName: s, provider: p.name}, tgs)
			}

			select {
			case m.triggerSend <- struct{}{}:
			default:
			}
		}
	}
}

func (m *Manager) sender(ctx context.Context) {
	ticker := time.NewTicker(m.updatert)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C: // Some discoverers send updates too often so we throttle these with the ticker.
			select {
			case <-m.triggerSend:
				m.metrics.sentUpdates.Inc()
				select {
				case m.syncCh <- m.allGroups():
				default:
					m.metrics.delayedUpdates.Inc()
					level.Debug(m.logger).Log("msg", "discovery receiver's channel was full so will retry the next cycle")
					select {
					case m.triggerSend <- struct{}{}:
					default:
					}
				}
			default:
			}
		}
	}
}

func (m *Manager) cancelDiscoverers() {
	for _, c := range m.discoverCancel {
		c()
	}
}

func (m *Manager) updateGroup(poolKey poolKey, tgs []*target.Group) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, ok := m.Targets[poolKey]; !ok {
		m.Targets[poolKey] = make(map[string]*target.Group)
	}
	for _, tg := range tgs {
		if tg != nil { // Some Discoverers send nil target group so need to check for it to avoid panics.
			m.Targets[poolKey][tg.Source] = tg
		}
	}
}

func (m *Manager) allGroups() map[string][]*target.Group {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	tSets := map[string][]*target.Group{}
	n := map[string]int{}
	for pkey, tsets := range m.Targets {
		for _, tg := range tsets {
			// Even if the target group 'tg' is empty we still need to send it to the 'Scrape manager'
			// to signal that it needs to stop all scrape loops for this target set.
			tSets[pkey.setName] = append(tSets[pkey.setName], tg)
			n[pkey.setName] += len(tg.Targets)
		}
	}
	for setName, v := range n {
		m.metrics.discoveredTargets.WithLabelValues(setName).Set(float64(v))
	}
	return tSets
}

// registerProviders returns a number of failed SD config.
func (m *Manager) registerProviders(cfgs Configs, setName string) int {
	var failed int
	add := func(cfg Config) {
		for _, p := range m.providers {
			if reflect.DeepEqual(cfg, p.config) {
				p.subs = append(p.subs, setName)
				return
			}
		}
		typ := cfg.Name()
		d, err := cfg.NewDiscoverer(DiscovererOptions{
			Logger: log.With(m.logger, "discovery", typ),
		})
		if err != nil {
			level.Error(m.logger).Log("msg", "Cannot create service discovery", "err", err, "type", typ)
			failed++
			return
		}
		m.providers = append(m.providers, &provider{
			name:   fmt.Sprintf("%s/%d", typ, len(m.providers)),
			d:      d,
			config: cfg,
			subs:   []string{setName},
		})
		//	added = true
	}
	for _, cfg := range cfgs {
		add(cfg)
	}

	return failed
}
