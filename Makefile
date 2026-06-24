.PHONY: all crossbuild build build-static build-debug snap

all: crossbuild

crossbuild:
	DOCKER_CLI_EXPERIMENTAL="enabled" docker run \
		--rm \
		--privileged \
		-v "/var/run/docker.sock:/var/run/docker.sock" \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-v "$(GOPATH)/pkg/mod":/go/pkg/mod \
		-w "/__w/parca-agent/parca-agent" \
		docker.io/goreleaser/goreleaser-cross:v1.22.4 \
		release --snapshot --clean --skip=publish --verbose

# Default build: dynamically linked so go-nvml can dlopen libnvidia-ml at
# runtime for GPU metrics. Requires cgo (CGO_ENABLED=1, the default).
build:
	go build -o parca-agent -buildvcs=false -tags osusergo,netgo

# Fully-static build without NVML GPU metrics. go-nvml cannot dlopen in a static
# binary, so the "nonvml" tag swaps in a no-op producer (gpumetrics/nvidia_stub.go).
build-static:
	go build -o parca-agent -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo,nonvml

build-debug:
	go build -o parca-agent-debug -buildvcs=false -tags osusergo,netgo -gcflags "all=-N -l"

snap: crossbuild
	cp ./dist/metadata.json snap/local/metadata.json

	cp ./dist/linux-amd64_linux_amd64_v1/parca-agent snap/local/parca-agent
	snapcraft pack --verbose --build-for amd64

	cp ./dist/linux-arm64_linux_arm64/parca-agent snap/local/parca-agent
	snapcraft pack --verbose --build-for arm64
