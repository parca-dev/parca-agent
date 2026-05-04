.PHONY: all crossbuild build build-debug snap probes-bpf

GOARCH ?= $(shell go env GOARCH)
PROBES_BPF_OBJ := probes/bpf/probe.bpf.$(GOARCH)
CLANG ?= clang

all: crossbuild

probes-bpf: $(PROBES_BPF_OBJ)

# Compiles the simple-probes-v1 uprobe program. Requires clang with the bpf
# target and libbpf headers (libbpf-dev / libbpf-devel).
$(PROBES_BPF_OBJ): probes/bpf/probe.bpf.c
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(GOARCH) \
		-Wall -Werror \
		-c $< -o $@

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

build: probes-bpf
	go build -o parca-agent -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo

build-debug: probes-bpf
	go build -o parca-agent-debug -buildvcs=false -ldflags="-extldflags=-static" -tags osusergo,netgo -gcflags "all=-N -l"

snap: crossbuild
	cp ./dist/metadata.json snap/local/metadata.json

	cp ./dist/linux-amd64_linux_amd64_v1/parca-agent snap/local/parca-agent
	snapcraft pack --verbose --build-for amd64

	cp ./dist/linux-arm64_linux_arm64/parca-agent snap/local/parca-agent
	snapcraft pack --verbose --build-for arm64
