package metadata

import (
	"context"
	"strings"
	"syscall"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type systemMetadataProvider struct {
	kernelMachine string
	kernelRelease string
	cfg           Config
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

func NewSystemMetadataProvider(cfg Config) (MetadataProvider, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return nil, err
	}

	return &systemMetadataProvider{
		kernelMachine: int8SliceToString(uname.Machine[:]),
		kernelRelease: int8SliceToString(uname.Release[:]),
		cfg:           cfg,
	}, nil
}

func (p *systemMetadataProvider) AddMetadata(_ context.Context, _ libpf.PID, lb *labels.Builder) bool {
	if p.cfg.Semconv {
		lb.Set("os.type", "linux")
		lb.Set("os.version", p.kernelRelease)
		switch p.kernelMachine {
		case "x86_64":
			lb.Set("host.arch", "amd64")
		case "aarch64":
			lb.Set("host.arch", "arm64")
		}
	}
	if p.cfg.discoveryLabels() {
		lb.Set("__meta_system_kernel_machine", p.kernelMachine)
		lb.Set("__meta_system_kernel_release", p.kernelRelease)
	}
	return true
}
