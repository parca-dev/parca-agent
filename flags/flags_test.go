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

package flags

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parca-dev/parca-agent/config"
)

func TestParse_OnlyRelabelConfigs(t *testing.T) {
	// Create a temporary config file with only relabel_configs
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `relabel_configs:
- source_labels: [__meta_process_executable_name]
  target_label: exec
  action: replace
- source_labels: [__meta_process_executable_compiler]
  target_label: compiler
  action: replace
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Set args with config path
	os.Args = []string{"parca-agent", "--config-path", configPath}
	
	// Parse flags
	flags, err := Parse()
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}
	
	// Verify default values are still set
	if flags.HTTPAddress != "127.0.0.1:7071" {
		t.Errorf("Expected default HTTPAddress, got %s", flags.HTTPAddress)
	}
	
	if flags.Log.Level != "info" {
		t.Errorf("Expected default log level 'info', got %s", flags.Log.Level)
	}
	
	// Also test config.LoadFile() to ensure relabel configs are loaded correctly
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}
	
	if cfg == nil {
		t.Fatal("Expected config to be loaded, got nil")
	}
	
	if len(cfg.RelabelConfigs) != 2 {
		t.Errorf("Expected 2 relabel configs, got %d", len(cfg.RelabelConfigs))
	}
	
	if len(cfg.RelabelConfigs) >= 2 {
		if cfg.RelabelConfigs[0].TargetLabel != "exec" {
			t.Errorf("Expected first relabel config target_label 'exec', got %s", cfg.RelabelConfigs[0].TargetLabel)
		}
		if cfg.RelabelConfigs[1].TargetLabel != "compiler" {
			t.Errorf("Expected second relabel config target_label 'compiler', got %s", cfg.RelabelConfigs[1].TargetLabel)
		}
	}
}

func TestParse_WithConfigFile_OnlyCLIFlags(t *testing.T) {
	// Create a temporary config file with only CLI flags
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `http-address: "0.0.0.0:8080"
log-level: debug
log-format: json
profiling-duration: 10s
profiling-cpu-sampling-frequency: 97
remote-store-address: grpc.example.com:443
remote-store-insecure: false
metadata-external-labels:
  cluster: production
  region: us-west-2
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Set args with config path
	os.Args = []string{"parca-agent", "--config-path", configPath}
	
	// Parse flags
	flags, err := Parse()
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}
	
	// Verify values from config file
	if flags.HTTPAddress != "0.0.0.0:8080" {
		t.Errorf("Expected HTTPAddress from config, got %s", flags.HTTPAddress)
	}
	
	if flags.Log.Level != "debug" {
		t.Errorf("Expected log level 'debug' from config, got %s", flags.Log.Level)
	}
	
	if flags.Log.Format != "json" {
		t.Errorf("Expected log format 'json' from config, got %s", flags.Log.Format)
	}
	
	if flags.Profiling.Duration != 10*time.Second {
		t.Errorf("Expected profiling duration 10s from config, got %v", flags.Profiling.Duration)
	}
	
	if flags.Profiling.CPUSamplingFrequency != 97 {
		t.Errorf("Expected CPU sampling frequency 97 from config, got %d", flags.Profiling.CPUSamplingFrequency)
	}
	
	if flags.RemoteStore.Address != "grpc.example.com:443" {
		t.Errorf("Expected remote store address from config, got %s", flags.RemoteStore.Address)
	}
	
	if flags.RemoteStore.Insecure != false {
		t.Errorf("Expected remote store insecure=false from config, got %v", flags.RemoteStore.Insecure)
	}
	
	if flags.Metadata.ExternalLabels["cluster"] != "production" {
		t.Errorf("Expected external label 'cluster=production' from config, got %s", flags.Metadata.ExternalLabels["cluster"])
	}
	
	if flags.Metadata.ExternalLabels["region"] != "us-west-2" {
		t.Errorf("Expected external label 'region=us-west-2' from config, got %s", flags.Metadata.ExternalLabels["region"])
	}
	
	// Also test config.LoadFile() - this config has no relabel configs
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}
	
	if cfg == nil {
		t.Fatal("Expected config to be loaded, got nil")
	}
	
	if len(cfg.RelabelConfigs) != 0 {
		t.Errorf("Expected 0 relabel configs, got %d", len(cfg.RelabelConfigs))
	}
}

func TestParse_WithConfigFile_BothRelabelAndCLIFlags(t *testing.T) {
	// Create a temporary config file with both relabel_configs and CLI flags
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `# Relabel configs
relabel_configs:
- source_labels: [__meta_process_executable_name]
  target_label: exec
  action: replace
- source_labels: [__meta_process_executable_compiler]
  target_label: compiler
  action: replace

# CLI flags
http-address: "0.0.0.0:9090"
log-level: warn
log-format: json
profiling-duration: 15s
profiling-label-ttl: 20m
profiling-enable-error-frames: true
remote-store-address: remote.parca.dev:443
remote-store-bearer-token-file: /etc/parca/token
remote-store-insecure-skip-verify: true
debuginfo-upload-disable: true
debuginfo-directories:
  - /usr/lib/debug
  - /var/lib/debug
bpf-verbose-logging: true
bpf-map-scale-factor: 2
offline-mode-storage-path: /var/lib/parca-agent
offline-mode-rotation-interval: 15m
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Set args with config path
	os.Args = []string{"parca-agent", "--config-path", configPath}
	
	// Parse flags
	flags, err := Parse()
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}
	
	// Verify CLI flags from config file
	if flags.HTTPAddress != "0.0.0.0:9090" {
		t.Errorf("Expected HTTPAddress from config, got %s", flags.HTTPAddress)
	}
	
	if flags.Log.Level != "warn" {
		t.Errorf("Expected log level 'warn' from config, got %s", flags.Log.Level)
	}
	
	if flags.Profiling.Duration != 15*time.Second {
		t.Errorf("Expected profiling duration 15s from config, got %v", flags.Profiling.Duration)
	}
	
	if flags.Profiling.LabelTTL != 20*time.Minute {
		t.Errorf("Expected label TTL 20m from config, got %v", flags.Profiling.LabelTTL)
	}
	
	if !flags.Profiling.EnableErrorFrames {
		t.Errorf("Expected enable_error_frames=true from config")
	}
	
	if flags.RemoteStore.Address != "remote.parca.dev:443" {
		t.Errorf("Expected remote store address from config, got %s", flags.RemoteStore.Address)
	}
	
	if flags.RemoteStore.BearerTokenFile != "/etc/parca/token" {
		t.Errorf("Expected bearer token file from config, got %s", flags.RemoteStore.BearerTokenFile)
	}
	
	if !flags.RemoteStore.InsecureSkipVerify {
		t.Errorf("Expected insecure_skip_verify=true from config")
	}
	
	if !flags.Debuginfo.UploadDisable {
		t.Errorf("Expected debuginfo upload_disable=true from config")
	}
	
	if len(flags.Debuginfo.Directories) != 2 {
		t.Errorf("Expected 2 debuginfo directories from config, got %d", len(flags.Debuginfo.Directories))
	}
	
	if !flags.BPF.VerboseLogging {
		t.Errorf("Expected BPF verbose_logging=true from config")
	}
	
	if flags.BPF.MapScaleFactor != 2 {
		t.Errorf("Expected BPF map_scale_factor=2 from config, got %d", flags.BPF.MapScaleFactor)
	}
	
	if flags.OfflineMode.StoragePath != "/var/lib/parca-agent" {
		t.Errorf("Expected offline mode storage_path from config, got %s", flags.OfflineMode.StoragePath)
	}
	
	if flags.OfflineMode.RotationInterval != 15*time.Minute {
		t.Errorf("Expected offline mode rotation_interval=15m from config, got %v", flags.OfflineMode.RotationInterval)
	}
	
	// Also test config.LoadFile() to ensure relabel configs are loaded correctly
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}
	
	if cfg == nil {
		t.Fatal("Expected config to be loaded, got nil")
	}
	
	if len(cfg.RelabelConfigs) != 2 {
		t.Errorf("Expected 2 relabel configs, got %d", len(cfg.RelabelConfigs))
	}
	
	if len(cfg.RelabelConfigs) >= 2 {
		if cfg.RelabelConfigs[0].TargetLabel != "exec" {
			t.Errorf("Expected first relabel config target_label 'exec', got %s", cfg.RelabelConfigs[0].TargetLabel)
		}
		if cfg.RelabelConfigs[1].TargetLabel != "compiler" {
			t.Errorf("Expected second relabel config target_label 'compiler', got %s", cfg.RelabelConfigs[1].TargetLabel)
		}
	}
}

func TestParse_WithConfigFile_CommandLineOverridesConfig(t *testing.T) {
	// Create a temporary config file with some CLI flags
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `http-address: "0.0.0.0:8080"
log-level: debug
profiling-duration: 10s
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Set args with config path and override some values
	os.Args = []string{
		"parca-agent",
		"--config-path", configPath,
		"--http-address", "127.0.0.1:9999",
		"--log-level", "error",
	}
	
	// Parse flags
	flags, err := Parse()
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}
	
	// Verify command-line args override config file values
	if flags.HTTPAddress != "127.0.0.1:9999" {
		t.Errorf("Expected HTTPAddress from command line, got %s", flags.HTTPAddress)
	}
	
	if flags.Log.Level != "error" {
		t.Errorf("Expected log level 'error' from command line, got %s", flags.Log.Level)
	}
	
	// Verify config file value that wasn't overridden
	if flags.Profiling.Duration != 10*time.Second {
		t.Errorf("Expected profiling duration 10s from config, got %v", flags.Profiling.Duration)
	}
	
	// Also test config.LoadFile() - this config has no relabel configs
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}
	
	if cfg == nil {
		t.Fatal("Expected config to be loaded, got nil")
	}
	
	if len(cfg.RelabelConfigs) != 0 {
		t.Errorf("Expected 0 relabel configs, got %d", len(cfg.RelabelConfigs))
	}
}

func TestParse_WithConfigFile_EmptyConfig(t *testing.T) {
	// Create an empty config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Set args with config path
	os.Args = []string{"parca-agent", "--config-path", configPath}
	
	// Parse flags - should not error, just use defaults
	flags, err := Parse()
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}
	
	// Verify default values are set
	if flags.HTTPAddress != "127.0.0.1:7071" {
		t.Errorf("Expected default HTTPAddress, got %s", flags.HTTPAddress)
	}
	
	if flags.Log.Level != "info" {
		t.Errorf("Expected default log level 'info', got %s", flags.Log.Level)
	}
	
	// Also test config.LoadFile() - empty config should return ErrEmptyConfig
	_, err = config.LoadFile(configPath)
	if err == nil {
		t.Error("Expected error when loading empty config file, got nil")
	}
	if !errors.Is(err, config.ErrEmptyConfig) {
		t.Errorf("Expected ErrEmptyConfig, got %v", err)
	}
}