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

DOCKER_SOCK ?= /var/run/docker.sock

# version:
ifeq ($(GITHUB_BRANCH_NAME),)
	BRANCH := $(shell $(CMD_GIT) rev-parse --abbrev-ref HEAD)-
else
	BRANCH := $(GITHUB_BRANCH_NAME)-
endif
COMMIT_TIMESTAMP := $(shell $(CMD_GIT) show --no-patch --format=%ct)-
ifeq ($(GITHUB_SHA),)
	COMMIT := $(shell $(CMD_GIT) rev-parse --short=8 HEAD)
else
	COMMIT := $(shell echo $(GITHUB_SHA) | cut -c1-8)
endif
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(shell $(CMD_GIT) describe --tags || echo '$(subst /,-,$(BRANCH))$(COMMIT_TIMESTAMP)$(COMMIT)'))

# renovate: datasource=docker depName=docker.io/goreleaser/goreleaser-cross
GOLANG_CROSS_VERSION := v1.21.0

# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go')
OUT_BIN := $(OUT_DIR)/parca-agent
OUT_BIN_DEBUG := $(OUT_DIR)/parca-agent-debug
OUT_BIN_EH_FRAME := $(OUT_DIR)/eh-frame
OUT_DOCKER ?= ghcr.io/parca-dev/parca-agent
DOCKER_BUILDER ?= parca-dev/cross-builder

LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_DIR := $(OUT_DIR)/libbpf/$(ARCH)
LIBBPF_HEADERS := $(LIBBPF_DIR)/usr/include
LIBBPF_OBJ := $(LIBBPF_DIR)/libbpf.a

VMLINUX := vmlinux.h
BPF_ROOT := bpf
BPF_SRC := $(BPF_ROOT)/cpu/cpu.bpf.c
OUT_BPF_DIR := pkg/profiler/cpu/bpf/$(ARCH)
OUT_BPF := $(OUT_BPF_DIR)/cpu.bpf.o

# CGO build flags:
PKG_CONFIG ?= pkg-config
CGO_CFLAGS_STATIC =-I$(abspath $(LIBBPF_HEADERS))
CGO_CFLAGS ?= $(CGO_CFLAGS_STATIC)
CGO_LDFLAGS_STATIC = -fuse-ld=ld -lzstd $(abspath $(LIBBPF_OBJ))
CGO_LDFLAGS ?= $(CGO_LDFLAGS_STATIC)

CGO_EXTLDFLAGS =-extldflags=-static
CGO_CFLAGS_DYN = -I$(abspath $(LIBBPF_HEADERS))
CGO_LDFLAGS_DYN = -L$(abspath $(LIBBPF_DIR)) -fuse-ld=ld -lelf -lz -lbpf

# possible other CGO flags:
# CGO_CPPFLAGS ?=
# CGO_CXXFLAGS ?=
# CGO_FFLAGS ?=

# libbpf build flags:
CFLAGS ?= -g -O2 -Werror -Wall -std=gnu89 -fpic -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
LDFLAGS ?= -fuse-ld=ld

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

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BPF) $(OUT_BIN) $(OUT_BIN_EH_FRAME)

GO_ENV := CGO_ENABLED=1 GOOS=linux GOARCH=$(ARCH) CC="$(CMD_CC)"
CGO_ENV := CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)"
GO_BUILD_FLAGS := -tags osusergo,netgo -mod=readonly -trimpath -v
GO_BUILD_DEBUG_FLAGS := -tags osusergo,netgo -v

ifndef DOCKER
$(OUT_BIN): libbpf $(filter-out *_test.go,$(GO_SRC)) go/deps | $(OUT_DIR)
	find dist -exec touch -t 202101010000.00 {} +
	$(GO_ENV) $(CGO_ENV) $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -o $@ ./cmd/parca-agent
else
$(OUT_BIN): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$@ VERSION=$(VERSION))
endif

.PHONY: run
run:
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) run $(SANITIZERS) ./cmd/parca-agent --log-level=debug | tee -i parca-agent.log

.PHONY: debug/build
debug/build: $(OUT_BIN_DEBUG)

$(OUT_BIN_DEBUG): libbpf $(filter-out *_test.go,$(GO_SRC)) go/deps | $(OUT_DIR)
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) build $(SANITIZERS) $(GO_BUILD_DEBUG_FLAGS) -gcflags="all=-N -l" -o $@ ./cmd/parca-agent

.PHONY: build-dyn
build-dyn: $(OUT_BPF) libbpf
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) -o $(OUT_DIR)/parca-agent ./cmd/parca-agent

$(OUT_BIN_EH_FRAME): go/deps
	find dist -exec touch -t 202101010000.00 {} +
	$(GO) build $(SANITIZERS) -tags osusergo -mod=readonly -trimpath -v -o $@ ./cmd/eh-frame

write-dwarf-unwind-tables: build
	make -C testdata validate EH_FRAME_BIN=../dist/eh-frame
	make -C testdata validate-compact EH_FRAME_BIN=../dist/eh-frame

test-dwarf-unwind-tables: write-dwarf-unwind-tables
	$(CMD_GIT) diff --exit-code testdata/

.PHONY: go/deps
go/deps: $(GO_SRC)
	$(GO) mod tidy

.PHONY: go/deps-check
go/deps-check: go/deps
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" govulncheck ./...

# bpf build:
.PHONY: bpf
bpf: $(OUT_BPF)

ifndef DOCKER
$(OUT_BPF): $(BPF_SRC) libbpf | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(MAKE) -C bpf build
	cp bpf/out/$(ARCH)/cpu.bpf.o $(OUT_BPF)
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
	test -d $(LIBBPF_SRC) || (echo "missing libbpf source - maybe do '$(CMD_GIT) submodule init && $(CMD_GIT) submodule update'" ; false)

$(LIBBPF_HEADERS) $(LIBBPF_HEADERS)/bpf $(LIBBPF_HEADERS)/linux: | $(OUT_DIR) libbpf_compile_tools $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" install_headers install_uapi_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH)

$(LIBBPF_OBJ): | $(OUT_DIR) libbpf_compile_tools $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" OBJDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH) BUILD_STATIC_ONLY=1

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# static analysis:
lint: check-license go/lint

lint-fix: go/lint-fix bpf/lint-fix

.PHONY: check-license
check-license:
	./scripts/check-license.sh

.PHONY: go/lint
go/lint: go/deps-check
	mkdir -p $(OUT_BPF_DIR)
	touch $(OUT_BPF)
	$(GO_ENV) $(CGO_ENV) golangci-lint run

.PHONY: go/lint-fix
go/lint-fix:
	mkdir -p $(OUT_BPF_DIR)
	touch $(OUT_BPF)
	$(GO_ENV) $(CGO_ENV) golangci-lint run --fix

.PHONY: bpf/lint-fix
bpf/lint-fix:
	$(MAKE) -C bpf lint-fix

test/profiler: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf
	sudo $(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) -v ./pkg/profiler/... -count=1

test/integration: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf
	sudo $(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) -v ./test/integration/... -count=1

.PHONY: test
ifndef DOCKER
test: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(OUT_BPF) test/profiler
	$(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) -v -count=1 -timeout 30s $(shell $(GO) list -find ./... | grep -Ev "pkg/profiler|e2e|test/integration")
else
test: $(DOCKER_BUILDER)
	$(call docker_builder_make,$@)
endif

cputest-static: build
	$(GO_ENV) $(CGO_ENV) $(GO) test -v ./pkg/profiler/cpu -c $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)"
	mv cpu.test kerneltest/

initramfs: cputest-static
	bluebox -e kerneltest/cpu.test
	mv initramfs.cpio kerneltest

vmtest: initramfs
	./kerneltest/vmtest.sh

.PHONY: format
format: go/fmt bpf/fmt

.PHONY: format-check
format-check: go/fmt-check bpf/fmt-check

.PHONY: bpf/fmt
bpf/fmt:
	$(MAKE) -C bpf format

.PHONY: bpf/fmt-check
bpf/fmt-check:
	$(MAKE) -C bpf format-check

.PHONY: go/fmt
go/fmt:
	gofumpt -w -extra $(shell $(GO) list -f '{{.Dir}}' -find ./...)

.PHONY: go/fmt-check
go/fmt-check:
	@test -z "$(shell gofumpt -d -extra $(shell $(GO) list -f '{{.Dir}}' -find ./...) | tee /dev/stderr)"

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
	$(MAKE) -C bpf clean
	-rm -rf $(OUT_DIR)
	-rm -f kerneltest/cpu.test
	-rm -f kerneltest/logs/vm_log_*.txt
	-rm -f kerneltest/kernels/linux-*.bz
	-rm -rf pkg/profiler/cpu/bpf/
	-rm -rf dist/
	-rm -rf goreleaser/dist/

# container:
.PHONY: container
container: $(OUT_DIR)
	podman build \
		--platform linux/amd64,linux/arm64 \
		--timestamp 0 \
		--manifest $(OUT_DOCKER):$(VERSION) .

.PHONY: container-docker
container-docker:
	docker build -t parca-dev/parca-agent:dev .

.PHONY: container-dev
container-dev:
	docker build -t parca-dev/parca-agent:dev -f Dockerfile.dev .

.PHONY: sign-container
sign-container:
	crane digest $(OUT_DOCKER):$(VERSION)
	cosign sign --yes -a GIT_HASH=$(COMMIT) -a GIT_VERSION=$(VERSION) $(OUT_DOCKER)@$(shell crane digest $(OUT_DOCKER):$(VERSION))

.PHONY: push-container
push-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://$(OUT_DOCKER):$(VERSION)

.PHONY: push-container-latest
push-container-latest:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://$(OUT_DOCKER):latest

.PHONY: push-signed-quay-container
push-signed-quay-container:
	cosign copy $(OUT_DOCKER):$(VERSION) quay.io/parca/parca:$(VERSION)

.PHONY: push-quay-container
push-quay-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://quay.io/parca/parca-agent:$(VERSION)

.PHONY: push-local-container
push-local-container:
	podman push $(OUT_DOCKER):$(VERSION) docker-daemon:docker.io/$(OUT_DOCKER):$(VERSION)

# other artifacts:
$(OUT_DIR)/help.txt:
	# The default value of --node is dynamic and depends on the current host's name
	# so we replace it with something static.
	rm -f tmp/help.txt
	$(OUT_BIN) --help | sed 's/--node=".*" */--node="hostname"           /' >$@

DOC_VERSION := "latest"
.PHONY: deploy/manifests
deploy/manifests:
	$(MAKE) -C deploy VERSION=$(DOC_VERSION) manifests

README.md: $(OUT_DIR)/help.txt deploy/manifests
	$(CMD_EMBEDMD) -w README.md

# local development:
.PHONY: dev/up
dev/up: deploy/manifests
	source ./scripts/local-dev-cluster.sh && up

.PHONY: dev/down
dev/down:
	source ./scripts/local-dev-cluster.sh && down

.PHONY: dev/up
observable-dev/up: deploy/manifests
	source ./scripts/local-dev-observable-cluster.sh && up

.PHONY: dev/down
observable-dev/down:
	source ./scripts/local-dev-observable-cluster.sh && down

E2E_KUBECONTEXT := parca-e2e

.PHONY: actions-e2e
actions-e2e:
	# If running locally, first run:
	#    minikube --profile=$(E2E_KUBECONTEXT) start --driver=virtualbox
	./e2e/ci-e2e.sh $(VERSION) $(E2E_KUBECONTEXT)
	$(GO) test -v ./e2e --context "$(E2E_KUBECONTEXT)"
	# If running locally, you can now delete the cluster:
	#    minikube --profile=$(E2E_KUBECONTEXT) delete

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
release-dry-run: $(DOCKER_BUILDER) bpf libbpf
	$(CMD_DOCKER) run \
		--rm \
		--privileged \
		-v "$(DOCKER_SOCK):/var/run/docker.sock" \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-v "$(GOPATH)/pkg/mod":/go/pkg/mod \
		-w /__w/parca-agent/parca-agent \
		$(DOCKER_BUILDER):$(GOLANG_CROSS_VERSION) \
		release --clean --auto-snapshot --skip-validate --skip-publish --debug

.PHONY: release-build
release-build: $(DOCKER_BUILDER) bpf libbpf
	$(CMD_DOCKER) run \
		--rm \
		--privileged \
		-v "$(DOCKER_SOCK):/var/run/docker.sock" \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-v "$(GOPATH)/pkg/mod":/go/pkg/mod \
		-w /__w/parca-agent/parca-agent \
		$(DOCKER_BUILDER):$(GOLANG_CROSS_VERSION) \
		build --clean --skip-validate --snapshot --debug
