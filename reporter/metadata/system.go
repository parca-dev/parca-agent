package metadata

import (
	"strings"
	"syscall"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"github.com/prometheus/prometheus/model/labels"
)

type systemMetadataProvider struct {
	kernelMachine string
	kernelRelease string
}

func int8SliceToString(arr []int8) string {
	var b strings.Builder
	for _, v := range arr {
		// NUL byte, as it's a C string.
		if v == 0 {
			break
		}
		b.WriteByte(byte(v))
	}
	return b.String()
}

func NewSystemMetadataProvider() (MetadataProvider, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return nil, err
	}

	return &systemMetadataProvider{
		kernelMachine: int8SliceToString(uname.Machine[:]),
		kernelRelease: int8SliceToString(uname.Release[:]),
	}, nil
}

func (p *systemMetadataProvider) AddMetadata(_ libpf.PID, lb *labels.Builder) bool {
	lb.Set("__meta_system_kernel_machine", p.kernelMachine)
	lb.Set("__meta_system_kernel_release", p.kernelRelease)
	return true
}
