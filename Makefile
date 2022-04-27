.PHONY: all
all: bpf build

SHELL := /bin/bash

ALL_ARCH ?= amd64 arm64

# tools:
CMD_LLC ?= llc
CMD_CLANG ?= clang
CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_EMBEDMD ?= embedmd
# environment:
ARCH_UNAME := $(shell uname -m)

# sanitizer config:
ENABLE_ASAN := no

ifeq ($(ENABLE_ASAN), yes)
	SANITIZER ?= -asan
endif

ifeq ($(ARCH_UNAME), x86_64)
	ARCH ?= amd64
else
	ARCH ?= arm64
endif

ifeq ($(ARCH), amd64)
	LINUX_ARCH ?= x86_64=x86
else
	LINUX_ARCH ?= aarch64=arm64
endif

KERN_RELEASE ?= $(shell uname -r)
KERN_BLD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BLD_PATH)))
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
# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go')
OUT_BIN := $(OUT_DIR)/parca-agent
OUT_BIN_DEBUG_INFO := $(OUT_DIR)/debug-info
BPF_SRC := parca-agent.bpf.c
VMLINUX := vmlinux.h
OUT_BPF_DIR := pkg/profiler
OUT_BPF := $(OUT_BPF_DIR)/parca-agent.bpf.o
BPF_HEADERS := 3rdparty/include
BPF_BUNDLE := $(OUT_DIR)/parca-agent.bpf.tar.gz
LIBBPF_SRC := 3rdparty/libbpf/src
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/usr/include
LIBBPF_OBJ := $(OUT_DIR)/libbpf/libbpf.a
OUT_DOCKER ?= ghcr.io/parca-dev/parca-agent
DOCKER_BUILDER ?= parca-agent-builder

# DOCKER_BUILDER_KERN_SRC(/BLD) is where the docker builder looks for kernel headers
DOCKER_BUILDER_KERN_BLD ?= $(if $(shell readlink $(KERN_BLD_PATH)),$(shell readlink $(KERN_BLD_PATH)),$(KERN_BLD_PATH))
DOCKER_BUILDER_KERN_SRC ?= $(if $(shell readlink $(KERN_SRC_PATH)),$(shell readlink $(KERN_SRC_PATH)),$(KERN_SRC_PATH))
# DOCKER_BUILDER_KERN_SRC_MNT is the kernel headers directory to mount into the docker builder container. DOCKER_BUILDER_KERN_SRC should usually be a descendent of this path.
DOCKER_BUILDER_KERN_SRC_MNT ?= $(dir $(DOCKER_BUILDER_KERN_SRC))

.PHONY: build
build: $(OUT_BIN) $(OUT_BIN_DEBUG_INFO)

$(OUT_DIR):
	mkdir -p $@

.PHONY: go/deps
go/deps:
	go mod tidy -compat=1.17

go_env := GOOS=linux GOARCH=$(ARCH:x86_64=amd64) CC=$(CMD_CLANG) CGO_CFLAGS="-I $(abspath $(LIBBPF_HEADERS))" CGO_LDFLAGS="$(abspath $(LIBBPF_OBJ))"
ifndef DOCKER
$(OUT_BIN): $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(filter-out *_test.go,$(GO_SRC)) $(BPF_BUNDLE) go/deps | $(OUT_DIR)
	find dist -exec touch -t 202101010000.00 {} +
	$(go_env) go build $(SANITIZER) -tags osusergo,netgo --ldflags="-extldflags=-static" -trimpath -v -o $(OUT_BIN) ./cmd/parca-agent
else
$(OUT_BIN): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$@ VERSION=$(VERSION))
endif

.PHONY: build-dyn
build-dyn:
	$(go_env) go build $(SANITIZER) -tags osusergo,netgo -trimpath -v -o $(OUT_BIN) ./cmd/parca-agent

ifndef DOCKER
$(OUT_BIN_DEBUG_INFO): go/deps
	find dist -exec touch -t 202101010000.00 {} +
	CGO_ENABLED=0 go build $(SANITIZER) -trimpath -v -o $(OUT_BIN_DEBUG_INFO) ./cmd/debug-info
else
$(OUT_BIN_DEBUG_INFO): $(DOCKER_BUILDER) go/deps | $(OUT_DIR)
	$(call docker_builder_make,$@ VERSION=$(VERSION))
endif

lint: check-license
	$(go_env) golangci-lint run

bpf_compile_tools = $(CMD_LLC) $(CMD_CLANG)
.PHONY: $(bpf_compile_tools)
$(bpf_compile_tools): % : check_%

$(LIBBPF_SRC):
	test -d $(LIBBPF_SRC) || (echo "missing libbpf source - maybe do 'git submodule init && git submodule update'" ; false)

$(LIBBPF_HEADERS) $(LIBBPF_HEADERS)/bpf $(LIBBPF_HEADERS)/linux: | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC) install_headers install_uapi_headers DESTDIR=$(abspath $(OUT_DIR))/libbpf

$(LIBBPF_OBJ): | $(OUT_DIR) $(bpf_compile_tools) $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(abspath $(OUT_DIR))/libbpf BUILD_STATIC_ONLY=1

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf_bundle_dir := $(OUT_DIR)/parca-agent.bpf
$(BPF_BUNDLE): $(BPF_SRC) $(LIBBPF_HEADERS)/bpf $(BPF_HEADERS)
	mkdir -p $(bpf_bundle_dir)
	cp $$(find $^ -type f) $(bpf_bundle_dir)

.PHONY: bpf
bpf: $(OUT_BPF) bpf/target/bpfel-unknown-none/release/cpu-profiler

.PHONY: bpf/target/bpfel-unknown-none/release/cpu-profiler
bpf/target/bpfel-unknown-none/release/cpu-profiler: bpf/cpu-profiler
	make -C bpf build
	cp bpf/target/bpfel-unknown-none/release/cpu-profiler pkg/profiler/cpu-profiler.bpf.o


ifndef DOCKER
$(OUT_BPF): $(BPF_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) | $(OUT_DIR) $(bpf_compile_tools)
	mkdir -p $(OUT_BPF_DIR)
	@v=$$($(CMD_CLANG) --version); test $$(echo $${v#*version} | head -n1 | cut -d '.' -f1) -ge '9' || (echo 'required minimum clang version: 9' ; false)
	$(CMD_CLANG) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-I $(LIBBPF_HEADERS)/bpf \
		-I $(BPF_HEADERS) \
		-Wno-address-of-packed-member \
		-Wno-compare-distinct-pointer-types \
		-Wno-deprecated-declarations \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-pointer-sign \
		-Wno-pragma-once-outside-header \
		-Wno-unknown-warning-option \
		-Wno-unused-value \
		-Wdate-time \
		-Wunused \
		-Wall \
		-fno-stack-protector \
		-fno-jump-tables \
		-fno-unwind-tables \
		-fno-asynchronous-unwind-tables \
		-xc \
		-nostdinc \
		-target bpf \
		-O2 -emit-llvm -c -g $< -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)
else
$(OUT_BPF): $(DOCKER_BUILDER) | $(OUT_DIR)
	$(call docker_builder_make,$@)
endif

test/profiler: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf
	sudo $(go_env) go test -v $(shell go list ./... | grep "pkg/profiler") $(SANITIZER)

.PHONY: test
ifndef DOCKER
test: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) bpf test/profiler
	$(go_env) go test -v $(shell go list ./... | grep -v "internal/pprof" | grep -v "pkg/profiler")
else
test: $(DOCKER_BUILDER)
	$(call docker_builder_make,$@)
endif

.PHONY: vet
ifndef DOCKER
vet: $(GO_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ)
	$(go_env) go vet -v $(shell go list ./... | grep -v "internal/pprof")
else
test: $(DOCKER_BUILDER)
	$(call docker_builder_make,$@)
endif

# record built image id to prevent unnecessary building and for cleanup
docker_builder_file := $(OUT_DIR)/$(DOCKER_BUILDER)
.PHONY: $(DOCKER_BUILDER)
$(DOCKER_BUILDER) $(docker_builder_file) &: Dockerfile.builder | $(OUT_DIR) check_$(CMD_DOCKER)
	$(CMD_DOCKER) build -t $(DOCKER_BUILDER) --iidfile $(docker_builder_file) - < $<

# docker_builder_make runs a make command in the parca-agent-builder container
define docker_builder_make
	$(CMD_DOCKER) run --rm \
	-v $(abspath $(DOCKER_BUILDER_KERN_SRC_MNT)):$(DOCKER_BUILDER_KERN_SRC_MNT) \
	-v $(abspath .):/parca-agent/parca-agent \
	-w /parca-agent/parca-agent \
	--entrypoint make $(DOCKER_BUILDER) KERN_BLD_PATH=$(DOCKER_BUILDER_KERN_BLD) KERN_SRC_PATH=$(DOCKER_BUILDER_KERN_SRC) $(1)
endef

.PHONY: mostlyclean
mostlyclean:
	-rm -rf $(OUT_BIN) $(bpf_bundle_dir) $(OUT_BPF) $(BPF_BUNDLE)

.PHONY: clean
clean:
	rm -f $(OUT_BPF)
	-FILE="$(docker_builder_file)" ; \
	if [ -r "$$FILE" ] ; then \
		$(CMD_DOCKER) rmi "$$(< $$FILE)" ; \
	fi
	-rm -rf dist $(OUT_DIR)
	$(MAKE) -C $(LIBBPF_SRC) clean

check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

.PHONY: container
container:
	./make-containers.sh $(OUT_DOCKER):$(VERSION)

.PHONY: sign-container
sign-container:
	cosign sign --force -a GIT_HASH=$(COMMIT) -a GIT_VERSION=$(VERSION) $(OUT_DOCKER)@$(shell podman inspect $(OUT_DOCKER):$(VERSION) --format "{{ .Digest }}")

.PHONY: push-container
push-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://$(OUT_DOCKER):$(VERSION)

.PHONY: push-signed-quay-container
push-signed-quay-container:
	cosign copy $(OUT_DOCKER):$(VERSION) quay.io/parca/parca:$(VERSION)

.PHONY: push-quay-container
push-quay-container:
	podman manifest push --all $(OUT_DOCKER):$(VERSION) docker://quay.io/parca/parca-agent:$(VERSION)

.PHONY: internal/pprof
internal/pprof:
	rm -rf internal/pprof
	rm -rf tmp
	git clone https://github.com/google/pprof tmp/pprof
	mkdir -p internal
	cp -r tmp/pprof/internal internal/pprof
	find internal/pprof -type f -exec sed -i 's/github.com\/google\/pprof\/internal/github.com\/parca-dev\/parca-agent\/internal\/pprof/g' {} +
	rm -rf tmp

$(OUT_DIR)/help.txt: $(OUT_BIN)
	$(OUT_BIN) --help > $@

DOC_VERSION := "latest"
.PHONY: deploy/manifests
deploy/manifests:
	$(MAKE) -C deploy VERSION=$(DOC_VERSION) manifests

README.md: $(OUT_DIR)/help.txt deploy/manifests
	$(CMD_EMBEDMD) -w README.md

.PHONY: format
format: go/fmt c/fmt

.PHONY: c/fmt
c/fmt:
	clang-format -i --style=LLVM $(BPF_SRC)

.PHONY: go/fmt
go/fmt:
	gofumpt -l -w $(shell go list ./... | grep -E -v "internal/pprof|internal/go" | sed 's#^github.com/parca-dev/parca-agent/##')
	go fmt $(shell go list ./... | grep -E -v "internal/pprof|internal/go")

.PHONY: check-license
check-license:
	./scripts/check-license.sh

.PHONY: dev/up
dev/up: deploy/manifests
	source ./scripts/local-dev.sh && up

.PHONY: dev/down
dev/down:
	source ./scripts/local-dev.sh && down
