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

package kernel

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/klauspost/compress/gzip"
)

type ebpfOption struct {
	name string
	// Used for specifying synonymous kernel options
	alternatives []string
}

var ebpfOptions = []ebpfOption{
	{name: "CONFIG_BPF"},
	{name: "CONFIG_BPF_SYSCALL"},
	{name: "CONFIG_HAVE_EBPF_JIT"},
	{name: "CONFIG_BPF_JIT"},
	{name: "CONFIG_BPF_JIT_ALWAYS_ON", alternatives: []string{"CONFIG_ARCH_WANT_DEFAULT_BPF_JIT"}},
	{name: "CONFIG_BPF_EVENTS"},
}

// CheckBPFEnabled returns non-nil error if all required kconfig options for running the BPF program are NOT enabled.
func CheckBPFEnabled() error {
	for _, dir := range []string{"/proc", "/boot"} {
		if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("failed to read directory %q, it does not exist", dir)
			}
			if os.IsPermission(err) {
				return fmt.Errorf("failed to read directory %q, agent does not have access", dir)
			}
			return err
		}
	}

	uname, err := unameRelease()
	if err != nil {
		return err
	}
	configPaths := []string{
		"/proc/config.gz",
		"/boot/config",
		"/boot/config-" + uname,
	}

	var result error
	for _, configPath := range configPaths {
		if _, err := os.Stat(configPath); err != nil {
			if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
				continue
			}
			result = errors.Join(result, err)
			continue
		}
		isBPFEnabled, err := checkBPFOptions(configPath)
		if err != nil {
			return err
		}
		// The only success case.
		if isBPFEnabled {
			return nil
		}
	}

	if result != nil {
		return result
	}

	// If we reach this point, either we have not found a config file or required options are not enabled.
	return fmt.Errorf("kernel config not found, tried paths: %s", strings.Join(configPaths, ", "))
}

func checkBPFOption(kernelConfig map[string]string, option string) (bool, error) {
	value, found := kernelConfig[option]
	if !found {
		return false, fmt.Errorf("kernel config required for eBPF not found, Config Option:%s", option)
	}

	if value != "y" && value != "m" {
		return false, fmt.Errorf("kernel config required for eBPF is disabled, Config Option:%s", option)
	}
	return true, nil
}

func checkBPFOptions(configFile string) (bool, error) {
	kernelConfig, err := getConfig(configFile)
	if err != nil {
		return false, err
	}

	for _, option := range ebpfOptions {
		// Check for the 'primary' ebpf kernel option
		found, err := checkBPFOption(kernelConfig, option.name)

		if !found && len(option.alternatives) == 0 {
			return found, err
		}

		if err != nil {
			// Iterate over the list of alternative options and check them sequentially
			var altFound bool
			for _, alt := range option.alternatives {
				if altFound, _ = checkBPFOption(kernelConfig, alt); altFound {
					// We only need one of the alternatives specified, so stop searching if found
					break
				}
			}

			// If we reach this point, we were unable to verify the presence of *any* alternatives
			if !altFound {
				alts := strings.Join(option.alternatives, ", ")
				return false, fmt.Errorf("%w; alternatives checked: %s", err, alts)
			}
		}
	}
	return true, nil
}

func getConfig(configFile string) (map[string]string, error) {
	var (
		kernelConfig map[string]string
		err          error
	)
	location := strings.TrimPrefix(configFile, "testdata") // Only valid for tests.
	switch {
	case strings.HasPrefix(location, "/proc"):
		kernelConfig, err = readConfigFromProc(configFile)
	case strings.HasPrefix(location, "/boot"):
		kernelConfig, err = readConfigFromBoot(configFile)
	default:
		kernelConfig, err = readConfigFromBoot(configFile)
	}
	if err != nil {
		return nil, err
	}

	return kernelConfig, nil
}

func readConfigFromBoot(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var (
		s            = bufio.NewScanner(file)
		kernelConfig = make(map[string]string)
	)
	if err = parse(s, kernelConfig); err != nil {
		return kernelConfig, err
	}
	return kernelConfig, nil
}

func readConfigFromProc(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	zreader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer zreader.Close()

	var (
		s            = bufio.NewScanner(zreader)
		kernelConfig = make(map[string]string)
	)
	if err = parse(s, kernelConfig); err != nil {
		return kernelConfig, err
	}

	return kernelConfig, nil
}
