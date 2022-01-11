module github.com/parca-dev/parca-agent

go 1.16

require (
	github.com/alecthomas/kong v0.3.0
	github.com/aquasecurity/libbpfgo v0.2.3-libbpf-0.6.1
	github.com/cespare/xxhash/v2 v2.1.2
	github.com/containerd/cgroups v1.0.2
	github.com/containerd/containerd v1.5.9
	github.com/docker/docker v20.10.12+incompatible
	github.com/go-kit/log v0.2.0
	github.com/google/pprof v0.0.0-20210609004039-a478d1d731e9
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/ianlancetaylor/demangle v0.0.0-20200824232613-28f6c0f3b639
	github.com/minio/highwayhash v1.0.2
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/oklog/run v1.1.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/parca-dev/parca v0.0.0-20210831075758-4d575344697c
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.32.1
	github.com/prometheus/prometheus v2.5.0+incompatible
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20210831042530-f4d43177bf5e
	google.golang.org/grpc v1.43.0
	k8s.io/api v0.23.1
	k8s.io/apimachinery v0.23.1
	k8s.io/client-go v0.23.1
	k8s.io/cri-api v0.23.1
)

replace github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20201130085533-a6e18916ab40
