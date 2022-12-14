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
		return "", fmt.Errorf("could not unpack BTF file: %s", err.Error())
	}

	return unpackBTFFile, nil
}

// unpackBTFHub unpacks tailored, to the compiled eBPF object, BTF files for kernel supported by BTFHub.
func unpackBTFHub(outFilePath string) error {
	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		return fmt.Errorf("could not get OS info: %s", err.Error())
	}

	if err := os.MkdirAll(filepath.Dir(outFilePath), 0755); err != nil {
		return fmt.Errorf("could not create temp dir: %s", err.Error())
	}

	osId := osInfo.GetOSReleaseFieldValue(helpers.OS_ID)
	versionId := strings.Replace(osInfo.GetOSReleaseFieldValue(helpers.OS_VERSION_ID), "\"", "", -1)
	kernelRelease := osInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	arch := osInfo.GetOSReleaseFieldValue(helpers.OS_ARCH)
	btfFilePath := fmt.Sprintf("dist/btfhub/%s/%s/%s/%s.btf", osId, versionId, arch, kernelRelease)

	btfFile, err := embed.BPFBundle.Open(btfFilePath)
	if err != nil {
		return fmt.Errorf("error opening embedded btfhub file: %s", err.Error())
	}
	defer btfFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("could not create btf file: %s", err.Error())
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, btfFile); err != nil {
		return fmt.Errorf("error copying embedded btfhub file: %s", err.Error())

	}

	return nil
}
