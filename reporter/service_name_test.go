package reporter

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// TestServiceNameFor pins the fallback order. service.name is the only place
// OTLP lets a resource name itself, and consumers key resource identity on it,
// so an empty value makes every profiled process anonymous downstream.
func TestServiceNameFor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		apmName  string
		comm     string
		execPath string
		want     string
	}{
		{
			name:     "apm name wins when the process named itself",
			apmName:  "checkout-service",
			comm:     "java",
			execPath: "/usr/bin/java",
			want:     "checkout-service",
		},
		{
			name:     "comm is the fallback, and is what top shows",
			comm:     "redis-server",
			execPath: "/usr/local/bin/redis-server",
			want:     "redis-server",
		},
		{
			// The kernel caps comm at TASK_COMM_LEN-1, so a long name arrives
			// truncated. Preferred anyway: it is what an operator sees.
			name:     "a truncated comm is still preferred",
			comm:     "my-very-long-p",
			execPath: "/opt/my-very-long-process-name",
			want:     "my-very-long-p",
		},
		{
			name:     "executable basename when comm is absent",
			execPath: "/usr/local/bin/redis-server",
			want:     "redis-server",
		},
		{
			name: "empty when nothing identifies the process",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceNameFor(tc.apmName, libpf.NewCommFromString(tc.comm), libpf.Intern(tc.execPath))
			require.Equal(t, tc.want, got)
		})
	}
}
