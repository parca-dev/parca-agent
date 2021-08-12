module github.com/parca-dev/parca-agent

go 1.16

require (
	github.com/alecthomas/kong v0.2.17
	github.com/aquasecurity/libbpfgo v0.1.1-0.20210531203451-ec279db45ec6
	github.com/containerd/containerd v1.5.4 // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/go-kit/kit v0.11.0
	github.com/google/pprof v0.0.0-20210609004039-a478d1d731e9
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/ianlancetaylor/demangle v0.0.0-20200824232613-28f6c0f3b639
	github.com/minio/highwayhash v1.0.2
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/oklog/run v1.1.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/parca-dev/parca v0.0.0-20210809093136-2790c84a495e
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/prometheus v2.5.0+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20210603081109-ebe580a85c40
	google.golang.org/grpc v1.38.0
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/client-go v0.20.6
	k8s.io/cri-api v0.20.6
)

replace github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20201130085533-a6e18916ab40

replace github.com/parca-dev/parca => ../parca
