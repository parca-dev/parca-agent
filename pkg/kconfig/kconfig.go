// Copyright 2022 The Parca Authors
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

package kconfig

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"strings"
)

const (
	ContainerCgroupPath = "/proc/1/cgroup"
	StackUnwinder       = "CONFIG_UNWINDER_FRAME_POINTER"
)

// TODO(vthakkar): Add more locations for scanning the config
// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122
var (
	configPaths = []string{
		"/proc/config.gz",
		"/boot/config",
		"/boot/config-%s",
	}
)

var ebpfCheckOptions = []string{
	"CONFIG_BPF",
	"CONFIG_BPF_SYSCALL",
	"CONFIG_HAVE_EBPF_JIT",
	"CONFIG_BPF_JIT",
	"CONFIG_BPF_JIT_ALWAYS_ON",
	"CONFIG_BPF_EVENTS",
}

func IsBPFEnabled() (bool, error) {
	var e error

	KernelConfig, e := getConfig()
	if e != nil {
		return false, e
	}

	for _, option := range ebpfCheckOptions {
		value, found := KernelConfig[option]
		if !found {
			return false, fmt.Errorf("kernel Config required for ebpf not found, Config Option:%s", option)
		}

		if value != "y" {
			return false, fmt.Errorf("kernel Config required for ebpf is disabled, Config Option:%s", option)
		}
	}
	return true, nil
}

func IsStackUnwindingEnabled() (bool, error) {
	var e error

	KernelConfig, e := getConfig()
	if e != nil {
		return false, e
	}

	value, found := KernelConfig[StackUnwinder]
	if !found {
		return false, fmt.Errorf("kernel config required for frame pointer stack unwinder not found, Config Option:%s", StackUnwinder)
	}

	if value != "y" {
		return false, fmt.Errorf("kernel config for frame pointer stack unwinder is disabled, Config Option:%s", StackUnwinder)
	}
	return true, nil
}

func getConfig() (map[string]string, error) {
	var found bool
	KernelConfig := make(map[string]string)

	i, e := UnameRelease()
	if e != nil {
		return KernelConfig, e
	}

	for _, configPath := range configPaths {
		if strings.Contains(configPath, ".gz") {
			KernelConfig, e = readConfigFromProc(configPath)
		}

		if strings.Contains(configPath, "%s") {
			bootConf := fmt.Sprintf(configPath, i)
			KernelConfig, e = readConfigFromBoot(bootConf)
		}

		if e != nil {
			continue
		}

		if len(KernelConfig) > 0 {
			found = true
		}
	}

	if !found {
		return nil, fmt.Errorf("kernel config not found")
	}
	return KernelConfig, nil
}

func readConfigFromBoot(filename string) (map[string]string, error) {
	KernelConfig := make(map[string]string)

	f, err := os.Open(filename)
	if err != nil {
		return KernelConfig, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	if err = parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}

func readConfigFromProc(filename string) (map[string]string, error) {
	KernelConfig := make(map[string]string)

	f, err := os.Open(filename)
	if err != nil {
		return KernelConfig, err
	}
	defer f.Close()

	zreader, err := gzip.NewReader(f)
	if err != nil {
		return KernelConfig, err
	}
	defer zreader.Close()

	s := bufio.NewScanner(zreader)
	if err = parse(s, KernelConfig); err != nil {
		return KernelConfig, err
	}
	return KernelConfig, nil
}

// Returns true is the process is running in a container
// TODO: Add a container detection via Sched to cover more scenarios
// https://man7.org/linux/man-pages/man7/sched.7.html
func IsInContainer() (bool, error) {
	var f *os.File
	var err error
	var i int
	f, err = os.Open(ContainerCgroupPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	b := make([]byte, 1024)
	i, err = f.Read(b)
	if err != nil {
		return false, err
	}
	switch {
	// CGROUP V1 docker container
	case strings.Contains(string(b[:i]), "cpuset:/docker"):
		return true, nil
	// CGROUP V2 docker container
	case strings.Contains(string(b[:i]), "0::/\n"):
		return true, nil
	// k8s container
	case strings.Contains(string(b[:i]), "cpuset:/kubepods"):
		return true, nil
	}

	return false, nil
}
