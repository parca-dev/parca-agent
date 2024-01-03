SHELL := /usr/bin/env bash

# tools:
ZIG ?= zig
CC ?= $(ZIG) cc -target $(shell uname -m)-linux-musl
CMD_CC ?= $(CC)
CMD_LLC ?= llc
LLD ?= lld
CMD_LLD ?= $(LLD)
LD ?= $(LLD)
GO ?= go
CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_EMBEDMD ?= embedmd
PKG_CONFIG ?= pkg-config

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

# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go' -not -path './.devbox/*' -not -path './dist/*')
OUT_BIN := $(OUT_DIR)/parca-agent
OUT_BIN_DEBUG := $(OUT_DIR)/parca-agent-debug
OUT_BIN_EH_FRAME := $(OUT_DIR)/eh-frame
OUT_DOCKER ?= ghcr.io/parca-dev/parca-agent
DOCKER_BUILDER ?= parca-dev/agent-builder

LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_DIR := $(OUT_DIR)/libbpf/$(ARCH)
LIBBPF_HEADERS := $(LIBBPF_DIR)/usr/include
LIBBPF_OUT_DIR := $(LIBBPF_DIR)
LIBBPF_OBJ := $(LIBBPF_DIR)/libbpf.a

LIBELF_SRC := 3rdparty/libelf
LIBELF_DIR := $(OUT_DIR)/libelf/$(ARCH)
LIBELF_HEADERS := $(LIBELF_DIR)/include
LIBELF_OUT_DIR := $(LIBELF_DIR)/lib
LIBELF_OBJ := $(LIBELF_OUT_DIR)/libelf.a

LIBZ_SRC := 3rdparty/zlib
LIBZ_DIR := $(OUT_DIR)/libz/$(ARCH)
LIBZ_HEADERS := $(LIBZ_DIR)/include
LIBZ_OUT_DIR := $(LIBZ_DIR)/lib
LIBZ_OBJ := $(LIBZ_OUT_DIR)/libz.a

LIBZSTD_SRC := 3rdparty/zstd
LIBZSTD_DIR := $(OUT_DIR)/libzstd/$(ARCH)
LIBZSTD_HEADERS := $(LIBZSTD_DIR)/include
LIBZSTD_OUT_DIR := $(LIBZSTD_DIR)/lib
LIBZSTD_OBJ := $(LIBZSTD_OUT_DIR)/libzstd.a

VMLINUX := vmlinux.h
BPF_ROOT := bpf
BPF_SRC := $(BPF_ROOT)/unwinders/native.bpf.c
OUT_BPF_DIR := pkg/profiler/cpu/bpf/programs/objects/$(ARCH)
# TODO(kakkoyun): DRY.
OUT_BPF := $(OUT_BPF_DIR)/native.bpf.o
OUT_RBPERF := $(OUT_BPF_DIR)/rbperf.bpf.o
OUT_PYPERF := $(OUT_BPF_DIR)/pyperf.bpf.o
OUT_BPF_CONTAINED_DIR := pkg/contained/bpf/$(ARCH)
OUT_PID_NAMESPACE := $(OUT_BPF_CONTAINED_DIR)/pid_namespace.bpf.o

# CGO build flags:
PKG_CONFIG_PATH = $(abspath $(LIBZSTD_DIR)/lib/pkgconfig):$(abspath $(LIBZ_DIR)/lib/pkgconfig):$(abspath $(LIBELF_DIR)/lib/pkgconfig):$(abspath $(LIBBPF_DIR))
CGO_CFLAGS_STATIC = -I$(abspath $(LIBBPF_HEADERS))
CGO_LDFLAGS_STATIC = -L$(abspath $(LIBZ_OUT_DIR)) -L$(abspath $(LIBELF_OUT_DIR)) $(abspath $(LIBZSTD_OBJ)) $(abspath $(LIBBPF_OBJ))

CGO_CFLAGS_DYN = -I$(abspath $(LIBBPF_HEADERS))
CGO_LDFLAGS_DYN = -lbpf -lelf -lz -lzstd

CGO_CFLAGS ?= $(CGO_CFLAGS_STATIC)
CGO_LDFLAGS ?= $(CGO_LDFLAGS_STATIC)
CGO_EXTLDFLAGS =linkmode 'external' -extldflags=-static

# possible other CGO flags:
# CGO_CPPFLAGS ?=
# CGO_CXXFLAGS ?=
# CGO_FFLAGS ?=

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

.PHONY: init
init:
	curl -fsSL https://get.jetpack.io/devbox | bash
	curl -sfL https://direnv.net/install.sh | bash

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BPF) $(OUT_BIN) $(OUT_BIN_EH_FRAME)

GO_ENV := CGO_ENABLED=1 GOOS=linux GOARCH=$(ARCH)
CGO_ENV := CC="$(CMD_CC)" CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" PKG_CONFIG=""
GO_BUILD_FLAGS :=-tags osusergo,netgo -mod=readonly -trimpath -v
GO_BUILD_DEBUG_FLAGS :=-tags osusergo,netgo -v

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

.PHONY: build/debug
build/debug: $(OUT_BPF) $(OUT_BIN_DEBUG)

$(OUT_BIN_DEBUG): libbpf $(filter-out *_test.go,$(GO_SRC)) go/deps | $(OUT_DIR)
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) build $(SANITIZERS) $(GO_BUILD_DEBUG_FLAGS) -gcflags="all=-N -l" -o $@ ./cmd/parca-agent

.PHONY: build/dyn
build/dyn: $(OUT_BPF) $(OUT_BIN_EH_FRAME)
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) -o $(OUT_DIR)/parca-agent ./cmd/parca-agent

$(OUT_BIN_EH_FRAME): go/deps
	find dist -exec touch -t 202101010000.00 {} +
	$(GO_ENV) $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) -o $@ ./cmd/eh-frame

write-dwarf-unwind-tables: build
	$(MAKE) -C testdata validate EH_FRAME_BIN=../dist/eh-frame
	$(MAKE) -C testdata validate-compact EH_FRAME_BIN=../dist/eh-frame
	$(MAKE) -C testdata validate-final EH_FRAME_BIN=../dist/eh-frame

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
	mkdir -p $(OUT_BPF_DIR) $(OUT_BPF_CONTAINED_DIR)
	$(MAKE) -C bpf build
	# TODO(kakkoyun): DRY.
	cp bpf/out/$(ARCH)/native.bpf.o $(OUT_BPF)
	cp bpf/out/$(ARCH)/rbperf.bpf.o $(OUT_RBPERF)
	cp bpf/out/$(ARCH)/pyperf.bpf.o $(OUT_PYPERF)
	cp bpf/out/$(ARCH)/pid_namespace.bpf.o $(OUT_PID_NAMESPACE)
else
$(OUT_BPF): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$@)
endif

# libbpf build flags:
CFLAGS ?= -g -O2 -Werror -Wall -std=gnu89 -fpic -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
LDFLAGS ?= -fuse-ld=$(LD)

# libbpf build:
check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

libbpf_compile_tools = $(CMD_LLC) $(CMD_CC)
.PHONY: libbpf_compile_tools
$(libbpf_compile_tools): % : check_%

$(abspath $(OUT_DIR))/pkg-config:
	mkdir -p $(abspath $(OUT_DIR))/pkg-config

libbpf-configure-pkg-config: $(abspath $(OUT_DIR))/pkg-config
	cp $(abspath $(LIBZSTD_DIR)/lib/pkgconfig)/*.pc $(abspath $(OUT_DIR))/pkg-config
	cp $(abspath $(LIBZ_DIR)/lib/pkgconfig)/*.pc $(abspath $(OUT_DIR))/pkg-config
	# TODO(kakkoyun): Add pc files for libelf.
	cp $(abspath $(LIBELF_DIR)/lib/pkgconfig)/*.pc $(abspath $(OUT_DIR))/pkg-config || true

.PHONY: libbpf
libbpf: libelf libbpf-configure-pkg-config $(LIBBPF_HEADERS) $(LIBBPF_OBJ)

LIBBPF_CFLAGS=$(CFLAGS) -I$(abspath $(LIBZ_HEADERS)) -I$(abspath $(LIBZSTD_HEADERS)) -I$(abspath $(LIBELF_HEADERS))
LIBBPF_LDFLAGS=$(LDFLAGS) -L$(abspath $(LIBZ_OBJ)) -L$(abspath $(LIBZSTD_OBJ)) -L$(abspath $(LIBELF_OBJ))

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || (echo "missing libbpf source - maybe do '$(CMD_GIT) submodule init && $(CMD_GIT) submodule update'" ; false)

# NOTICE:
# Older versions of pkg-config do not support the PKG_CONFIG_PATH variable.
# So we need to set PKG_CONFIG_LIBDIR instead.

$(LIBBPF_HEADERS) $(LIBBPF_HEADERS)/bpf $(LIBBPF_HEADERS)/linux: | $(OUT_DIR) libbpf_compile_tools $(LIBBPF_SRC)
	PKG_CONFIG_LIBDIR=$(abspath $(OUT_DIR))/pkg-config PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(LIBBPF_CFLAGS)" LDFLAGS="$(LIBBPF_LDFLAGS)" install_headers install_uapi_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH)

$(LIBBPF_OBJ): | $(OUT_DIR) libbpf_compile_tools $(LIBBPF_SRC)
	PKG_CONFIG_LIBDIR=$(abspath $(OUT_DIR))/pkg-config PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(LIBBPF_CFLAGS)" LDFLAGS="$(LIBBPF_LDFLAGS)" install_pkgconfig DESTDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH) PREFIX=$(abspath $(OUT_DIR))/libbpf/$(ARCH)
	PKG_CONFIG_LIBDIR=$(abspath $(OUT_DIR))/pkg-config PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(MAKE) -C $(LIBBPF_SRC) CC="$(CMD_CC)" CFLAGS="$(LIBBPF_CFLAGS)" LDFLAGS="$(LIBBPF_LDFLAGS)" OBJDIR=$(abspath $(OUT_DIR))/libbpf/$(ARCH) PREFIX=$(abspath $(OUT_DIR))/libbpf/$(ARCH) BUILD_STATIC_ONLY=1

LIBELF_CFLAGS=-fno-omit-frame-pointer -fpic -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-but-set-parameter -Wno-unused-but-set-variable -I$(abspath $(LIBZ_HEADERS)) -I$(abspath $(LIBZSTD_HEADERS))
LIBELF_LDFLAGS=$(LDFLAGS) -L$(abspath $(LIBZ_OUT_DIR)) -L$(abspath $(LIBZSTD_OUT_DIR))

.PHONY: libelf
libelf: zlib zstd $(LIBELF_HEADERS) $(LIBELF_OBJ)

$(LIBELF_SRC):
	test -d $(LIBELF_SRC) || (echo "missing libelf source - maybe do '$(CMD_GIT) submodule init && $(CMD_GIT) submodule update'" ; false)

$(LIBELF_HEADERS) $(LIBELF_HEADERS)/libelfelf.h $(LIBELF_HEADERS)/elf.h $(LIBELF_HEADERS)/gelf.h $(LIBELF_HEADERS)/nlist.h: | $(OUT_DIR) libbpf_compile_tools $(LIBELF_SRC)

$(LIBELF_OBJ): | $(OUT_DIR) $(LIBELF_SRC)
	$(MAKE) -C $(LIBELF_SRC) CC="$(CMD_CC)" CFLAGS="$(LIBELF_CFLAGS)" LDFLAGS="$(LIBELF_LDFLAGS)"
	$(MAKE) -C $(LIBELF_SRC) CC="$(CMD_CC)" CFLAGS="$(LIBELF_CFLAGS)" LDFLAGS="$(LIBELF_LDFLAGS)" install-static PREFIX=$(abspath $(OUT_DIR))/libelf/$(ARCH)

.PHONY: zlib
zlib: $(LIBZ_HEADERS) $(LIBZ_OBJ)

$(LIBZ_SRC):
	test -d $(LIBZ_SRC) || (echo "missing zlib source - maybe do '$(CMD_GIT) submodule init && $(CMD_GIT) submodule update'" ; false)

$(LIBZ_HEADERS) $(LIBZ_HEADERS)/zconf.h $(LIBZ_HEADERS)/zlib.h: | $(OUT_DIR) libbpf_compile_tools $(LIBZ_SRC)

$(LIBZ_OBJ): | $(OUT_DIR) libbpf_compile_tools $(LIBZ_SRC)
	cd $(LIBZ_SRC) && \
	CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
	./configure --prefix=$(abspath $(OUT_DIR))/libz/$(ARCH) --static
	$(MAKE) -C $(LIBZ_SRC) CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)"
	$(MAKE) -C $(LIBZ_SRC) CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" install

.PHONY: zstd
zstd: $(LIBZSTD_HEADERS) $(LIBZSTD_OBJ)

$(LIBZSTD_SRC):
	test -d $(LIBZSTD_SRC) || (echo "missing zstd source - maybe do '$(CMD_GIT) submodule init && $(CMD_GIT) submodule update'" ; false)

$(LIBZSTD_HEADERS) $(LIBZSTD_HEADERS)/zdict.h $(LIBZSTD_HEADERS)/zstd.h: | $(OUT_DIR) libbpf_compile_tools $(LIBZSTD_SRC)

$(LIBZSTD_OBJ): | $(OUT_DIR) libbpf_compile_tools $(LIBZSTD_SRC)
	$(MAKE) -C $(LIBZSTD_SRC)/lib CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" install-includes PREFIX=$(abspath $(OUT_DIR))/libzstd/$(ARCH)
	$(MAKE) -C $(LIBZSTD_SRC)/lib CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" install-pc PREFIX=$(abspath $(OUT_DIR))/libzstd/$(ARCH)
	$(MAKE) -C $(LIBZSTD_SRC)/lib CC="$(CMD_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" install-static PREFIX=$(abspath $(OUT_DIR))/libzstd/$(ARCH)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# static analysis:
lint: check-license go/lint

lint-fix: go/lint-fix bpf/lint-fix

.PHONY: check-license
check-license:
	./scripts/check-license.sh

.PHONY: go/lint
go/lint:
	mkdir -p $(OUT_BPF_DIR) $(OUT_BPF_CONTAINED_DIR)
	touch $(OUT_BPF) $(OUT_PID_NAMESPACE)
	$(GO_ENV) $(CGO_ENV) golangci-lint run

.PHONY: go/lint-fix
go/lint-fix:
	mkdir -p $(OUT_BPF_DIR) $(OUT_BPF_CONTAINED_DIR)
	touch $(OUT_BPF) $(OUT_PID_NAMESPACE)
	$(GO_ENV) $(CGO_ENV) golangci-lint run --fix

.PHONY: bpf/lint-fix
bpf/lint-fix:
	$(MAKE) -C bpf lint-fix

test/profiler: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf
	sudo $(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -v ./pkg/profiler/... -count=1

test/integration: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf
	sudo --preserve-env=CI $(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -v ./test/integration/... -count=1

.PHONY: test
ifndef DOCKER
test: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(OUT_BPF) test/profiler
	$(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -v -count=1 -timeout 2m $(shell $(GO) list -find ./... | grep -Ev "pkg/profiler|e2e|test/integration")
else
test: $(DOCKER_BUILDER)
	$(call docker_builder_make,$@)
endif

cputest-static: build
	$(GO_ENV) $(CGO_ENV) $(GO) test $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -v ./pkg/profiler/cpu -c
	mv cpu.test test/kernel/

initramfs: cputest-static
	bluebox -e test/kernel/cpu.test
	mv initramfs.cpio test/kernel

test/kernel: initramfs
	./test/kernel/vmtest.sh

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
	-rm -f test/kernel/cpu.test
	-rm -f test/kernel/logs/vm_log_*.txt
	-rm -f test/kernel/kernels/linux-*.bz
	-rm -rf pkg/profiler/cpu/bpf/programs/objects/
	-rm -rf pkg/contained/bpf/
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

.PHONY: push-signed-gcr-container
push-signed-gcr-container:
	cosign copy $(OUT_DOCKER):$(VERSION) gcr.io/polar-signals-public/parca-agent:$(VERSION)

.PHONY: push-gcr-container
push-gcr-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://gcr.io/polar-signals-public/parca-agent:$(VERSION)

.PHONY: push-local-container
push-local-container:
	podman push $(OUT_DOCKER):$(VERSION) docker-daemon:docker.io/$(OUT_DOCKER):$(VERSION)

# other artifacts:
$(OUT_DIR)/help.txt:
	# The default value of --node is dynamic and depends on the current host's name
	# so we replace it with something static.
	$(OUT_BIN) --help | sed 's/--node=".*" */--node="hostname"           /' >$@

DOC_VERSION := "latest"
.PHONY: deploy/manifests
deploy/manifests:
	$(MAKE) -C deploy VERSION=$(DOC_VERSION) manifests

.PHONY: README.md
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
$(DOCKER_BUILDER): Dockerfile | check_$(CMD_DOCKER)
	$(CMD_DOCKER) build -t $(DOCKER_BUILDER):latest -f Dockerfile.builder .

# docker_builder_make runs a make command in the parca-agent-builder container
define docker_builder_make
	$(CMD_DOCKER) run --rm \
	-v $(abspath $(DOCKER_BUILDER_KERN_SRC_MNT)):$(DOCKER_BUILDER_KERN_SRC_MNT) \
	-v $(abspath .):/parca-agent/parca-agent \
	-w /parca-agent/parca-agent \
	--entrypoint make $(DOCKER_BUILDER) KERN_BLD_PATH=$(DOCKER_BUILDER_KERN_BLD) KERN_SRC_PATH=$(DOCKER_BUILDER_KERN_SRC) $(1)
endef

# test cross-compile release pipeline:
.PHONY: release/dry-run
release/dry-run: $(DOCKER_BUILDER) bpf libbpf
	$(CMD_DOCKER) run \
		--rm \
		--privileged \
		-v "$(DOCKER_SOCK):/var/run/docker.sock" \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-w /__w/parca-agent/parca-agent \
		$(DOCKER_BUILDER):latest \
		goreleaser release --clean --auto-snapshot --skip-validate --skip-publish --debug

.PHONY: release/build
release/build: $(DOCKER_BUILDER) bpf libbpf
	$(CMD_DOCKER) run \
		--rm \
		--privileged \
		-v "$(DOCKER_SOCK):/var/run/docker.sock" \
		-v "$(PWD):/__w/parca-agent/parca-agent" \
		-w /__w/parca-agent/parca-agent \
		$(DOCKER_BUILDER):latest \
		goreleaser build --clean --skip-validate --snapshot --debug
