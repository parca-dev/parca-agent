SHELL := /usr/bin/env bash

# tools:
GO ?= go
CMD_LLC ?= llc
CMD_CC ?= clang
CMD_DOCKER ?= docker
CMD_GIT ?= git
CMD_EMBEDMD ?= embedmd

# environment:
ARCH ?= $(shell go env GOARCH)

# renovate: datasource=docker depName=docker.io/nixos/nix
DOCKER_NIX_VERSION ?= 2.13.2
DOCKER_NIX_IMAGE ?= docker.io/nixos/nix:$(DOCKER_NIX_VERSION)
DOCKER_DEVSHELL_NAME ?= parca-agent-devshell

# version:
ifeq ($(GITHUB_BRANCH_NAME),)
	BRANCH := $(shell $(CMD_GIT) rev-parse --abbrev-ref HEAD)-
else
	BRANCH := $(GITHUB_BRANCH_NAME)-
endif
ifeq ($(GITHUB_SHA),)
	COMMIT := $(shell $(CMD_GIT) describe --no-match --dirty --always --abbrev=8)
else
	COMMIT := $(shell echo $(GITHUB_SHA) | cut -c1-8)
endif
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(shell $(CMD_GIT) describe --tags || echo '$(subst /,-,$(BRANCH))$(COMMIT)'))

# renovate: datasource=docker depName=docker.io/goreleaser/goreleaser-cross
GOLANG_CROSS_VERSION := v1.20.2

# inputs and outputs:
OUT_DIR ?= dist
GO_SRC := $(shell find . -type f -name '*.go')
OUT_BIN := $(OUT_DIR)/parca-agent
OUT_BIN_DEBUG := $(OUT_DIR)/parca-agent-debug
OUT_BIN_EH_FRAME := $(OUT_DIR)/eh-frame
OUT_DOCKER ?= ghcr.io/parca-dev/parca-agent

BPF_ROOT := bpf
BPF_SRC := $(BPF_ROOT)/cpu/cpu.bpf.c
OUT_BPF_DIR := pkg/profiler/cpu
OUT_BPF := $(OUT_BPF_DIR)/cpu-profiler.bpf.o

# CGO build flags:
CGO_LDFLAGS ?= -lbpf

CGO_EXTLDFLAGS = -extldflags=-static
CGO_LDFLAGS_DYN = -lbpf

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

version:
	@echo $(VERSION)

$(OUT_DIR):
	mkdir -p $@

.PHONY: build
build: $(OUT_BPF) $(OUT_BIN) $(OUT_BIN_EH_FRAME)

GO_ENV := CGO_ENABLED=1 GOOS=linux GOARCH=$(ARCH) CC="$(CMD_CC)"
CGO_ENV := CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)"
GO_BUILD_FLAGS := -tags osusergo,netgo -mod=vendor -trimpath -v
GO_BUILD_DEBUG_FLAGS := -tags osusergo,netgo -v

$(OUT_BIN): $(filter-out *_test.go,$(GO_SRC)) go/deps | $(OUT_DIR)
	find dist -exec touch -t 202101010000.00 {} +
	$(GO_ENV) $(CGO_ENV) $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -o $@ ./cmd/parca-agent

.PHONY: debug/build
debug/build: $(OUT_BIN_DEBUG)

$(OUT_BIN_DEBUG): $(filter-out *_test.go,$(GO_SRC)) go/deps | $(OUT_DIR)
	$(GO_ENV) $(CGO_ENV) $(GO) build $(GO_BUILD_DEBUG_FLAGS) --ldflags="$(CGO_EXTLDFLAGS)" -gcflags="all=-N -l" -o $@ ./cmd/parca-agent

.PHONY: build-dyn
build-dyn: $(OUT_BPF) libbpf
	$(GO_ENV) CGO_CFLAGS="$(CGO_CFLAGS_DYN)" CGO_LDFLAGS="$(CGO_LDFLAGS_DYN)" $(GO) build $(SANITIZERS) $(GO_BUILD_FLAGS) -o $(OUT_DIR)/parca-agent-dyn ./cmd/parca-agent

$(OUT_BIN_EH_FRAME): go/deps
	find dist -exec touch -t 202101010000.00 {} +
	$(GO) build $(SANITIZERS) -tags osusergo -mod=vendor -trimpath -v -o $@ ./cmd/eh-frame

write-dwarf-unwind-tables: build
	make -C testdata validate EH_FRAME_BIN=../dist/eh-frame
	make -C testdata validate-compact EH_FRAME_BIN=../dist/eh-frame

test-dwarf-unwind-tables: write-dwarf-unwind-tables
	$(CMD_GIT) diff --exit-code testdata/

.PHONY: go/deps
go/deps:
	$(GO) mod tidy
	$(GO) mod vendor

# bpf build:
.PHONY: bpf
bpf: $(OUT_BPF)

$(OUT_BPF): $(BPF_SRC) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(MAKE) -C bpf build
	cp bpf/cpu/cpu.bpf.o $(OUT_BPF)

check_%:
	@command -v $* >/dev/null || (echo "missing required tool $*" ; false)

# static analysis:
lint: check-license go/lint

lint-fix: go/lint-fix bpf/lint-fix

.PHONY: check-license
check-license:
	./scripts/check-license.sh

.PHONY: go/lint
go/lint:
	touch $(OUT_BPF)
	$(GO_ENV) $(CGO_ENV) golangci-lint run

.PHONY: go/lint-fix
go/lint-fix:
	touch $(OUT_BPF)
	$(GO_ENV) $(CGO_ENV) golangci-lint run --fix

.PHONY: bpf/lint-fix
bpf/lint-fix:
	$(MAKE) -C bpf lint-fix

test/profiler: $(GO_SRC) bpf
	sudo $(GO_ENV) $(CGO_ENV) $(GO) test $(SANITIZERS) -v ./pkg/profiler/...

test: $(GO_SRC) $(OUT_BPF) # test/profiler # TODO: Fix sudo with devshell
	$(GO) test $(SANITIZERS) -v $(shell $(GO) list -find ./... | grep -Ev "internal/pprof|pkg/profiler|e2e")

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
	gofumpt -w -extra $(shell $(GO) list -f '{{.Dir}}' -find ./... | grep -Ev "internal/pprof|internal/go")

.PHONY: go/fmt-check
go/fmt-check:
	@test -z "$(shell gofumpt -d -extra $(shell $(GO) list -f '{{.Dir}}' -find ./... | grep -Ev "internal/pprof|internal/go") | tee /dev/stderr)"

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
	$(MAKE) -C bpf clean
	-rm -rf $(OUT_DIR)
	-rm -f kerneltest/cpu.test
	-rm -f kerneltest/logs/vm_log_*.txt
	-rm -f kerneltest/kernels/linux-*.bz

# container:
.PHONY: container
container:
	nix build --print-build-logs --print-out-paths '.#docker-image'

.PHONY: container-dev
container-dev:
	nix build --print-build-logs --print-out-paths '.#docker-image-debug'

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

.PHONY: push-local-container
push-local-container:
	podman push $(OUT_DOCKER):$(VERSION) docker-daemon:docker.io/$(OUT_DOCKER):$(VERSION)

# vendor dependencies:
.PHONY: internal/pprof
internal/pprof:
	rm -rf internal/pprof
	rm -rf tmp
	$(CMD_GIT) clone https://github.com/google/pprof tmp/pprof
	mkdir -p internal
	cp -r tmp/pprof/internal internal/pprof
	find internal/pprof -type f -exec sed -i 's/github.com\/google\/pprof\/internal/github.com\/parca-dev\/parca-agent\/internal\/pprof/g' {} +
	rm -rf tmp

# other artifacts:
$(OUT_DIR)/help.txt: $(OUT_DIR)
	# The default value of --node is dynamic and depends on the current host's name
	# so we replace it with something static.
	$(OUT_BIN) --help | sed 's/--node=".*" */--node="hostname"           /' >$@

DOC_VERSION := "latest"
.PHONY: deploy/manifests
deploy/manifests:
	$(MAKE) -C deploy VERSION=$(DOC_VERSION) manifests

README.md: $(OUT_DIR)/help.txt
	$(CMD_EMBEDMD) -w README.md

# local development:
.PHONY: dev/up
dev/up: deploy/manifests
	source ./scripts/local-dev.sh && up

.PHONY: dev/down
dev/down:
	source ./scripts/local-dev.sh && down

E2E_KUBECONTEXT := parca-e2e

.PHONY: actions-e2e
actions-e2e:
	# If running locally, first run:
	#    minikube --profile=$(E2E_KUBECONTEXT) start --driver=virtualbox
	./e2e/ci-e2e.sh $(VERSION) $(E2E_KUBECONTEXT)
	$(GO) test -v ./e2e --context "$(E2E_KUBECONTEXT)"
	# If running locally, you can now delete the cluster:
	#    minikube --profile=$(E2E_KUBECONTEXT) delete

.PHONY: container-devshell-run
container-devshell-run:
	'$(CMD_DOCKER)' run  \
	--detach \
	--entrypoint=sh \
	--env=NIX_CONFIG="$$(printf 'experimental-features = nix-command flakes\nsandbox = true')" \
	--name '$(DOCKER_DEVSHELL_NAME)' \
	--privileged \
	--volume='$(abspath .):/parca-agent/parca-agent' \
	--workdir=/parca-agent/parca-agent \
	$(DOCKER_NIX_IMAGE) \
	-c 'while :; do sleep 84600; done'

.PHONY: container-devshell-exec
container-devshell-exec:
	'$(CMD_DOCKER)' exec --interactive --tty '$(DOCKER_DEVSHELL_NAME)' nix develop --accept-flake-config

container-devshell: container-devshell-run container-devshell-exec

.PHONY: container-devshell-destroy
container-devshell-destroy:
	'$(CMD_DOCKER)' stop '$(DOCKER_DEVSHELL_NAME)' && '$(CMD_DOCKER)' rm '$(DOCKER_DEVSHELL_NAME)'
