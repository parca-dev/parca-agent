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

package config_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/require"

	"github.com/parca-dev/parca-agent/pkg/config"
)

func setupReloader(ctx context.Context, t *testing.T) (*os.File, chan *config.Config) {
	t.Helper()

	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	reloadConfig := make(chan *config.Config, 1)

	filename := filepath.Join(t.TempDir(), "parca-agent.yaml")

	cfgStr := ""

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("failed to open temporary config file: %v", err)
	}

	if _, err := f.WriteString(cfgStr); err != nil {
		t.Errorf("failed to write temporary config file: %v", err)
	}

	reloaders := []config.ComponentReloader{
		{
			Name: "test",
			Reloader: func(cfg *config.Config) error {
				reloadConfig <- cfg
				return nil
			},
		},
	}

	cfgReloader, err := config.NewConfigReloader(logger, reg, filename, reloaders)
	if err != nil {
		t.Errorf("failed to instantiate config reloader: %v", err)
	}

	go cfgReloader.Run(ctx)

	time.Sleep(time.Millisecond * 100)

	return f, reloadConfig
}

func TestReloadValid(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*300)
	defer cancel()

	f, reloadConfig := setupReloader(ctx, t)
	defer f.Close()

	cfgStr := `relabel_configs:
- source_labels: [systemd_unit]
  regex: ''
  action: drop
`

	if _, err := f.WriteString(cfgStr); err != nil {
		t.Errorf("failed to update temporary config file: %v", err)
	}

	select {
	case cfg := <-reloadConfig:
		require.Equal(t, &config.Config{
			RelabelConfigs: []*relabel.Config{
				{
					SourceLabels: model.LabelNames{"systemd_unit"},
					Separator:    ";",
					Regex:        relabel.MustNewRegexp(``),
					Replacement:  "$1",
					Action:       relabel.Drop,
				},
			},
		}, cfg)
	case <-ctx.Done():
		t.Error("configuration reload timed out")
	}
}

func TestReloadInvalid(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*300)
	defer cancel()

	f, reloadConfig := setupReloader(ctx, t)
	defer f.Close()

	config := "{"

	if _, err := f.WriteString(config); err != nil {
		t.Errorf("failed to update temporary config file: %v", err)
	}

	select {
	case <-reloadConfig:
		t.Error("invalid configuration was reloaded")
	case <-ctx.Done():
	}
}

func TestReloadSymlink(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*300)
	defer cancel()
	logger := log.NewNopLogger()
	reg := prometheus.NewRegistry()
	reloadConfig := make(chan *config.Config, 1)

	tmpDir := t.TempDir()
	filenameOld := filepath.Join(tmpDir, "parca-agent_old.yaml")
	filenameNew := filepath.Join(tmpDir, "parca-agent_new.yaml")
	symlinkName := filepath.Join(tmpDir, "parca-agent.yaml")

	cfgStr := ""

	// Create old config file
	fold, err := os.OpenFile(filenameOld, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("failed to open config file: %v", err)
	}
	if _, err := fold.WriteString(cfgStr); err != nil {
		t.Errorf("failed to write old config file: %v", err)
	}
	fold.Close()

	// Create symlink to old config file
	if err := os.Symlink(filenameOld, symlinkName); err != nil {
		t.Errorf("failed to create symlink to old config file: %v", err)
	}

	cfgStr += `relabel_configs:
- source_labels: [systemd_unit]
  regex: ''
  action: drop
`

	// Create new config file
	fnew, err := os.OpenFile(filenameNew, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("failed to open new config file: %v", err)
	}
	if _, err := fnew.WriteString(cfgStr); err != nil {
		t.Errorf("failed to write new config file: %v", err)
	}
	fnew.Close()

	// Set up reloader
	reloaders := []config.ComponentReloader{
		{
			Name: "test",
			Reloader: func(cfg *config.Config) error {
				reloadConfig <- cfg
				return nil
			},
		},
	}

	cfgReloader, err := config.NewConfigReloader(logger, reg, symlinkName, reloaders)
	if err != nil {
		t.Errorf("failed to instantiate config reloader: %v", err)
	}

	go cfgReloader.Run(ctx)

	time.Sleep(time.Millisecond * 100)

	// Recreate symlink, but pointing to new config file
	if err := os.Remove(symlinkName); err != nil {
		t.Errorf("failed to remove symlink to old config file: %v", err)
	}
	if err := os.Symlink(filenameNew, symlinkName); err != nil {
		t.Errorf("failed to create symlink to new config file: %v", err)
	}
	// Delete old config file
	// Actually triggers the reload since the symlink was followed
	// when the watcher was created
	// https://github.com/fsnotify/fsnotify/issues/199
	// https://github.com/fsnotify/fsnotify/issues/394
	if err := os.Remove(filenameOld); err != nil {
		t.Errorf("failed to remove old config file: %v", err)
	}

	// Wait for reload
	select {
	case cfg := <-reloadConfig:
		require.Equal(t, &config.Config{
			RelabelConfigs: []*relabel.Config{
				{
					SourceLabels: model.LabelNames{"systemd_unit"},
					Separator:    ";",
					Regex:        relabel.MustNewRegexp(``),
					Replacement:  "$1",
					Action:       relabel.Drop,
				},
			},
		}, cfg)
	case <-ctx.Done():
		t.Error("configuration reload timed out")
	}
}
