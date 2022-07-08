SHELL := /usr/bin/env bash

# tools:
CC ?= gcc
CLANG ?= clang
GO ?= go
CMD_LLC ?= llc
CMD_CC ?= $(CLANG)
CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_EMBEDMD ?= embedmd

# environment:
ARCH ?= $(shell go env GOARCH)

# kernel headers:
KERN_RELEASE ?= $(shell uname -r)
KERN_BLD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BLD_PATH)))
# DOCKER_BUILDER_KERN_SRC(/BLD) is where the docker builder looks for kernel headers
DOCKER_BUILDER_KERN_BLD ?= $(if $(shell readlink $(KERN_BLD_PATH)),$(shell readlink $(KERN_BLD_PATH)),$(KERN_BLD_PATH))
DOCKER_BUILDER_KERN_SRC ?= $(if $(shell readlink $(KERN_SRC_PATH)),$(shell readlink $(KERN_SRC_PATH)),$(KERN_SRC_PATH))
# DOCKER_BUILDER_KERN_SRC_MNT is the kernel headers directory to mount into the docker builder container. DOCKER_BUILDER_KERN_SRC should usually be a descendent of this path.
DOCKER_BUILDER_KERN_SRC_MNT ?= $(dir $(DOCKER_BUILDER_KERN_SRC))

# version:
ifeq ($(GITHUB_BRANCH_NAME),)
	BRANCH := $(shell git rev-parse --abbrev-ref HEAD)-
else
	BRANCH := $(GITHUB_BRANCH_NAME)-
endif
ifeq ($(GITHUB_SHA),)
	COMMIT := $(shell git describe --no-match --dirty --always --abbrev=8)
else
	COMMIT := $(shell echo $(GITHUB_SHA) | cut -c1-8)
endif
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(shell $(CMD_GIT) describe --tags 2>/dev/null || echo '$(BRANCH)$(COMMIT)'))

# renovate: datasource=docker depName=docker.io/goreleaser/goreleaser-cross
GOLANG_CROSS_VERSION := v1.18.3

# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go')
OUT_BIN := $(OUT_DIR)/parca-agent
OUT_BIN_DEBUG_INFO := $(OUT_DIR)/debug-info
OUT_DOCKER ?= ghcr.io/parca-dev/parca-agent
DOCKER_BUILDER ?= parca-dev/cross-builder

LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/$(ARCH)/usr/include
LIBBPF_OBJ := $(OUT_DIR)/libbpf/$(ARCH)/libbpf.a

VMLINUX := vmlinux.h
BPF_ROOT := bpf
BPF_SRC := $(BPF_ROOT)/cpu-profiler
OUT_BPF_DIR := pkg/profiler
OUT_BPF := $(OUT_BPF_DIR)/cpu-profiler.bpf.o

# CGO build flags:
PKG_CONFIG ?= pkg-config
CGO_CFLAGS_STATIC =-I$(abspath $(LIBBPF_HEADERS))
CGO_CFLAGS ?= $(CGO_CFLAGS_STATIC)
CGO_LDFLAGS_STATIC = -fuse-ld=ld $(abspath $(LIBBPF_OBJ))
CGO_LDFLAGS ?= $(CGO_LDFLAGS_STATIC)

CGO_EXTLDFLAGS =-extldflags=-static
CGO_CFGLAGS_DYN =-I. -I/usr/include/
CGO_LDFLAGS_DYN =-fuse-ld=ld -lelf -lz -lbpf

# possible other CGO flags:
# CGO_CPPFLAGS ?=
# CGO_CXXFLAGS ?=
# CGO_FFLAGS ?=

# libbpf build flags:
# CFLAGS = -g -O2 -Wall -fpie
CFLAGS ?= -g -O2 -Werror -Wall -std=gnu89 # default CFLAGS
LDFLAGS ?= -fuse-ld=lld

# sanitizer config:
ENABLE_ASAN := no
ENABLE_RACE := no
ifeq ($(ENABLE_ASAN), yes)
	SANITIZERS += -asan
endif

ifeq ($(ENABLE_RACE), yes)
	SANITIZERS += -race
endif

.PHONY: all
all: build

# $(GOb uild:
$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BIN) $(OUT_BIN_DEBUG_INFO) $(OUT_BPF)

GO_ENV := CGO_ENABLED=1 GOOS=linux GOARCH=$(ARCH) CC="$(CMD_CC)"
CGO_ENV := CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)"
GO_BUILD_FLAGS := -tags osusergo,netgo -mod=readonly -trimpath -v

ifndef DOCKER
$(OUT_BIN): libbpf $(filter-out *_test.go,$(GO_SRC)) go/deps | $(OUT_DIR)
	find dist -exec touch -t 202101010000.00 {} +
	$(GO_ENV) $(CGO_ENV) $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -o $@ ./cmd/parca-agent
else
$(OUT_BIN): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$@ VERSION=$(VERSION))
endif

.PHONY: build-dyn
build-dyn: libbpf $(OUT_BPF)
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) -o $(OUT_DIR)/parca-agent-dyn ./cmd/parca-agent

ifndef DOCKER
$(OUT_BIN_DEBUG_INFO): go/deps
	find dist -exec touch -t 202101010000.00 {} +
	$(GO) build $(SANITIZERS) -trimpath -v -o $(OUT_BIN_DEBUG_INFO) ./cmd/debug-info
else
$(OUT_BIN_DEBUG_INFO): $(DOCKER_BUILDER) go/deps | $(OUT_DIR)
	$(call docker_builder_make,$@ VERSION=$(VERSION))
endif

.PHONY: go/deps
go/deps:
	$(GO) mod tidy -compat=1.17

# bpf build:
.PHONY: bpf
bpf: $(OUT_BPF)

ifndef DOCKER
$(OUT_BPF): $(BPF_SRC) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(MAKE) -C bpf build
	cp bpf/target/bpfel-unknown-none/release/cpu-profiler $(OUT_BPF)
else
$(OUT_BPF): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$@)
endif

# libbpf build:
.PHONY: libbpf
libbpf: $(LIBBPF_HEADERS) $(LIBBPF_OBJ)

check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

libbpf_compile_tools = $(CMD_LLC) $(CMD_CC)
.PHONY: libbpf_compile_tools
$(libbpf_compile_tools): % : check_%

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || (echo "missing libbpf source - maybe do 'git submodule init && git submodule update'" ; false)

$(LIBBPF_HEADERS) $(LIBBPF_HEADERS)/bpf $(LIBBPF_HEADERS)/linux: | $(OUT_DIR) libbpf_compile_tools $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" install_headers install_uapi_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH)

$(LIBBPF_OBJ): | $(OUT_DIR) libbpf_compile_tools $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" OBJDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH) BUILD_STATIC_ONLY=1

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# static analysis:
lint: check-license go/lint bpf/lint

.PHONY: check-license
check-license:
	./scripts/check-license.sh

.PHONY: go/lint
go/lint:
	$(GO_ENV) golangci-lint run

.PHONY: bpf/lint
bpf/lint:
	$(MAKE) -C bpf lint

test/profiler: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf
	sudo $(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) -v $(shell $(GO) list ./... | grep "pkg/profiler")

.PHONY: test
ifndef DOCKER
test: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(OUT_BPF) build test/profiler
	$(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) -v $(shell $(GO) list ./... | grep -v "internal/pprof" | grep -v "pkg/profiler" | grep -v "e2e")
else
test: $(DOCKER_BUILDER)
	$(call docker_builder_make,$@)
endif

.PHONY: format
format: go/fmt bpf/fmt

.PHONY: bpf/fmt
bpf/fmt:
	$(MAKE) -C bpf format

.PHONY: go/fmt
go/fmt:
	$(GO) fmt $(shell $(GO) list ./... | grep -E -v "internal/pprof|internal/go")

.PHONY: vet
ifndef DOCKER
vet: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ)
	$(GO_ENV) $(CGO_ENV) $(GO) vet -v $(shell $(GO) list ./... | grep -v "internal/pprof")
else
vet: $(DOCKER_BUILDER)
	$(call docker_builder_make,$@)
endif

# clean:
.PHONY: mostlyclean
mostlyclean:
	-rm -rf $(OUT_BIN) $(OUT_BPF)

.PHONY: clean
clean: mostlyclean
	-FILE="$(docker_builder_file)" ; \
	if [ -r "$$FILE" ] ; then \
		$(CMD_DOCKER) rmi "$$(< $$FILE)" ; \
	fi
	$(MAKE) -C $(LIBBPF_SRC) clean
	-rm -rf $(OUT_DIR)

# container:
.PHONY: container
container: $(OUT_DIR)
	podman build \
		--platform linux/amd64,linux/arm64 \
		--timestamp 0 \
		--tag $(OUT_DOCKER):$(VERSION) .

.PHONY: container-dev
container-dev:
	docker build -t parca-dev/parca-agent:dev --build-arg=GOLANG_BASE=golang:1.18.3-bullseye --build-arg=DEBIAN_BASE=debian:bullseye-slim .

.PHONY: sign-container
sign-container:
	crane digest $(OUT_DOCKER):$(VERSION)
	cosign sign --force -a GIT_HASH=$(COMMIT) -a GIT_VERSION=$(VERSION) $(OUT_DOCKER)@$(shell crane digest $(OUT_DOCKER):$(VERSION))

.PHONY: push-container
push-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://$(OUT_DOCKER):$(VERSION)

.PHONY: push-signed-quay-container
push-signed-quay-container:
	cosign copy $(OUT_DOCKER):$(VERSION) quay.io/parca/parca:$(VERSION)

.PHONY: push-quay-container
push-quay-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://quay.io/parca/parca-agent:$(VERSION)

# vendor dependencies:
.PHONY: internal/pprof
internal/pprof:
	rm -rf internal/pprof
	rm -rf tmp
	git clone https://github.com/google/pprof tmp/pprof
	mkdir -p internal
	cp -r tmp/pprof/internal internal/pprof
	find internal/pprof -type f -exec sed -i 's/github.com\/google\/pprof\/internal/github.com\/parca-dev\/parca-agent\/internal\/pprof/g' {} +
	rm -rf tmp

# other artifacts:
$(OUT_DIR)/help.txt: $(OUT_BIN)
	$(OUT_BIN) --help > $@

DOC_VERSION := "latest"
.PHONY: deploy/manifests
deploy/manifests:
	$(MAKE) -C deploy VERSION=$(DOC_VERSION) manifests

README.md: $(OUT_DIR)/help.txt deploy/manifests
	$(CMD_EMBEDMD) -w README.md

# local development:
.PHONY: dev/up
dev/up: deploy/manifests
	source ./scripts/local-dev.sh && up

.PHONY: dev/down
dev/down:
	source ./scripts/local-dev.sh && down

.PHONY: test-e2e $(driver)
test-e2e:
	cd deploy; source ./../e2e/local-e2e.sh && run $(driver)
	$(GO) test -v $(shell $(GO) list ./e2e)

.PHONY: $(DOCKER_BUILDER)
$(DOCKER_BUILDER): Dockerfile.cross-builder | $(OUT_DIR) check_$(CMD_DOCKER)
 	# Build an image on top of goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION} with the necessary dependencies.
	$(CMD_DOCKER) build -t $(DOCKER_BUILDER):$(GOLANG_CROSS_VERSION) --build-arg=GOLANG_CROSS_VERSION=$(GOLANG_CROSS_VERSION) - < $<

# docker_builder_make runs a make command in the parca-agent-builder container
define docker_builder_make
	$(CMD_DOCKER) run --rm \
	-v $(abspath $(DOCKER_BUILDER_KERN_SRC_MNT)):$(DOCKER_BUILDER_KERN_SRC_MNT) \
	-v $(abspath .):/parca-agent/parca-agent \
	-w /parca-agent/parca-agent \
	--entrypoint make $(DOCKER_BUILDER) KERN_BLD_PATH=$(DOCKER_BUILDER_KERN_BLD) KERN_SRC_PATH=$(DOCKER_BUILDER_KERN_SRC) $(1)
endef

# test cross-compile release pipeline:
.PHONY: release-dry-run
release-dry-run: $(DOCKER_BUILDER) bpf
	$(CMD_DOCKER) run \
		--rm \
		--privileged \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-w /__w/parca-agent/parca-agent \
		$(DOCKER_BUILDER):$(GOLANG_CROSS_VERSION) \
		release --rm-dist --auto-snapshot --skip-validate --skip-publish --debug

.PHONY: release-build
release-build: $(DOCKER_BUILDER) bpf
	$(CMD_DOCKER) run \
		--rm \
		--privileged \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-w /__w/parca-agent/parca-agent \
		$(DOCKER_BUILDER):$(GOLANG_CROSS_VERSION) \
		build --rm-dist --skip-validate --snapshot --debug
