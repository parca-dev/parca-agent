module github.com/polarsignals/polarsignals-agent

go 1.16

require (
	github.com/aquasecurity/libbpfgo v0.1.0
	github.com/containerd/containerd v1.5.0 // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/go-kit/kit v0.9.0
	github.com/google/pprof v0.0.0-20200229191704-1ebb73c60ed3
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20181102032728-5e5cf60278f6
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015
	google.golang.org/grpc v1.37.0
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/cri-api v0.21.0
)

replace github.com/aquasecurity/tracee/libbpfgo => github.com/brancz/tracee/libbpfgo v0.0.0-20210514070929-4cfeba8e0c36
