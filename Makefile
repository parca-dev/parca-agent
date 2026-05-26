.PHONY: all crossbuild build build-debug snap probes-bpf

GOARCH ?= $(shell go env GOARCH)
CLANG ?= clang

PROBES_BPF_OBJ := probes/bpf/probe.bpf.o

# On Debian-based systems (including the goreleaser-cross container)
# `linux-libc-dev` installs arch-specific headers under
# /usr/include/$(multiarch-tuple)/asm/, e.g. /usr/include/x86_64-linux-gnu/asm/.
# Clang's default search path is just /usr/include, so the #include <asm/types.h>
# inside linux/types.h fails to resolve unless we add the multiarch directory.
# `gcc -print-multiarch` returns the tuple on Debian-like distros and is empty
# elsewhere (Fedora ships /usr/include/asm/ directly, so no extra -I is needed).
# We use gcc rather than clang here because `-print-multiarch` is a Debian patch
# to gcc not always present in upstream clang.
MULTIARCH := $(shell gcc -print-multiarch 2>/dev/null)
BPF_CFLAGS := $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH))

all: crossbuild

# BPF compilation is host-architecture-independent: clang -target bpf emits
# the same bytecode regardless of where it runs. Our BPF program doesn't
# touch any arch-specific macros (PT_REGS_*, etc.), so a single object
# loads on amd64 and arm64 alike -- the embedded loader picks it without
# consulting runtime.GOARCH.
#
# If a future change adds PT_REGS_PARM1(ctx) or similar, the file will need
# to be compiled separately per arch with the matching -D__TARGET_ARCH_*
# flag; at that point this rule should grow per-target variables again.
#
# Requires clang + libbpf headers (libbpf-dev / libbpf-devel) + kernel UAPI
# headers (linux-libc-dev / kernel-headers) on the host. No cross-toolchain
# needed.
probes-bpf: $(PROBES_BPF_OBJ)

$(PROBES_BPF_OBJ): probes/bpf/probe.bpf.c
	$(CLANG) -O2 -g -target bpf \
		$(BPF_CFLAGS) \
		-Wall -Werror \
		-c $< -o $@

# crossbuild produces both amd64 and arm64 release binaries via goreleaser
# inside its cross container. Goreleaser doesn't invoke make, so we build
# the BPF object on the HOST first; the mounted workspace makes it visible
# inside the container for //go:embed to pick up.
crossbuild: probes-bpf
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
