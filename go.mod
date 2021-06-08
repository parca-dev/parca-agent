module github.com/polarsignals/polarsignals-agent

go 1.16

require (
	github.com/alecthomas/kong v0.2.16
	github.com/aquasecurity/libbpfgo v0.1.1-0.20210531203451-ec279db45ec6
	github.com/conprof/conprof v0.0.0-20210603071110-bea0b2086ac8
	github.com/containerd/containerd v1.5.0 // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/go-kit/kit v0.10.0
	github.com/google/pprof v0.0.0-20210601050228-01bbb1931b22
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/ianlancetaylor/demangle v0.0.0-20200824232613-28f6c0f3b639
	github.com/minio/highwayhash v1.0.2
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/oklog/run v1.1.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/prometheus/client_golang v1.10.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/thanos-io/thanos v0.21.0-rc.0
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015
	google.golang.org/grpc v1.37.0
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/client-go v0.20.6
	k8s.io/cri-api v0.20.6
)

replace github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20201130085533-a6e18916ab40
