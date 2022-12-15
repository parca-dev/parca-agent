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

package btf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	helpers "github.com/aquasecurity/libbpfgo/helpers"

	embed "github.com/parca-dev/parca-agent"
)

const DefaultBTFObjPath = "/sys/kernel/btf/vmlinux"

func ObjPath(installPath string) (string, error) {
	if helpers.OSBTFEnabled() {
		return DefaultBTFObjPath, nil
	}

	unpackBTFFile := filepath.Join(installPath, "parca-agent.btf")
	if err := unpackBTFHub(unpackBTFFile); err != nil {
		return "", fmt.Errorf("could not unpack BTF file: %w", err)
	}

	return unpackBTFFile, nil
}

// unpackBTFHub unpacks tailored, to the compiled eBPF object, BTF files for kernel supported by BTFHub.
func unpackBTFHub(outFilePath string) error {
	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		return fmt.Errorf("could not get OS info: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outFilePath), 0o755); err != nil {
		return fmt.Errorf("could not create temp dir: %w", err)
	}

	osID := osInfo.GetOSReleaseFieldValue(helpers.OS_ID)
	versionID := strings.ReplaceAll(osInfo.GetOSReleaseFieldValue(helpers.OS_VERSION_ID), "\"", "")
	kernelRelease := osInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	arch := osInfo.GetOSReleaseFieldValue(helpers.OS_ARCH)
	btfFilePath := fmt.Sprintf("dist/btfhub/%s/%s/%s/%s.btf", osID, versionID, arch, kernelRelease)

	btfFile, err := embed.BPFBundle.Open(btfFilePath)
	if err != nil {
		return fmt.Errorf("error opening embedded btfhub file: %w", err)
	}
	defer btfFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("could not create btf file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, btfFile); err != nil {
		return fmt.Errorf("error copying embedded btfhub file: %w", err)
	}

	return nil
}
