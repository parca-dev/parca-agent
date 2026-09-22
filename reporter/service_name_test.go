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
		env      map[string]string
		want     string
	}{
		{
			name:     "apm name wins when the process named itself",
			apmName:  "checkout-service",
			comm:     "java",
			execPath: "/usr/bin/java",
			env:      map[string]string{"OTEL_SERVICE_NAME": "from-env"},
			want:     "checkout-service",
		},
		{
			// The point of reading the environment at all: comm is the thread
			// name, so without this a JVM reports one resource per thread pool.
			name:     "OTEL_SERVICE_NAME outranks a thread name",
			comm:     "G1 Refine#0",
			execPath: "/usr/bin/java",
			env:      map[string]string{"OTEL_SERVICE_NAME": "checkout"},
			want:     "checkout",
		},
		{
			name:     "service.name in OTEL_RESOURCE_ATTRIBUTES",
			comm:     "java",
			execPath: "/usr/bin/java",
			env:      map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "host.arch=amd64,service.name=checkout,k=v"},
			want:     "checkout",
		},
		{
			// The precedence the OTel environment variable spec defines.
			name: "OTEL_SERVICE_NAME beats OTEL_RESOURCE_ATTRIBUTES",
			comm: "java",
			env: map[string]string{
				"OTEL_SERVICE_NAME":        "wins",
				"OTEL_RESOURCE_ATTRIBUTES": "service.name=loses",
			},
			want: "wins",
		},
		{
			name: "percent-encoded values are decoded",
			comm: "java",
			env:  map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=my%20service"},
			want: "my service",
		},
		{
			// Baggage allows a ";"-delimited metadata part that carries no
			// resource meaning, so it must not end up inside the name.
			name: "baggage metadata is stripped",
			comm: "java",
			env:  map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=checkout;prop=1"},
			want: "checkout",
		},
		{
			name: "an empty OTEL_SERVICE_NAME falls through rather than blanking the name",
			comm: "redis-server",
			env:  map[string]string{"OTEL_SERVICE_NAME": "  "},
			want: "redis-server",
		},
		{
			// service.namespace and service.name share a prefix; matching on
			// one must not pick up the other.
			name: "a key that merely starts with service.name is not a match",
			comm: "redis-server",
			env:  map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=shop"},
			want: "redis-server",
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
			var env map[libpf.String]libpf.String
			if tc.env != nil {
				env = make(map[libpf.String]libpf.String, len(tc.env))
				for k, v := range tc.env {
					env[libpf.Intern(k)] = libpf.Intern(v)
				}
			}

			got := serviceNameFor(tc.apmName, libpf.NewCommFromString(tc.comm),
				libpf.Intern(tc.execPath), env)
			require.Equal(t, tc.want, got)
		})
	}
}
