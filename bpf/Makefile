# renovate: datasource=github-releases depName=aya-rs/bpf-linker
BPF_LINKER_VERSION := v0.9.4

LLVM_SYS_140_PREFIX ?= /usr/lib/llvm-14

.PHONY: setup
setup:
	rustup show
	# we need to do this as we're using an external LLVM. See: https://github.com/aya-rs/bpf-linker#using-external-llvm
	# TODO(vadorovsky): Remove the LLVM_SYS_140_PREFIX variable once
	# https://gitlab.com/taricorp/llvm-sys.rs/-/merge_requests/22 is merged.
	LLVM_SYS_140_PREFIX=$(LLVM_SYS_140_PREFIX) cargo install --locked --git https://github.com/aya-rs/bpf-linker --tag $(BPF_LINKER_VERSION) --no-default-features --features system-llvm -- bpf-linker

.PHONY: build
build: clang
	cargo xtask build-ebpf --release

.PHONY: clean
clean:
	cargo clean
	rm -f $(OUT_BPF)

.PHONY: format
format: c/fmt
	cargo fmt

.PHONY: c/fmt
c/fmt:
	clang-format -i --style=LLVM $(BPF_SRC)

.PHONY: format-check
format-check:
	cargo fmt --check

.PHONY: lint
lint:
	cargo clippy
	cargo doc

lint-fix:
	cargo clippy --fix

# environment:
ALL_ARCH ?= amd64 arm64
ARCH_UNAME := $(shell uname -m)
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

# tools:
CLANG ?= clang
CMD_LLC ?= llc
CMD_CC ?= $(CLANG)

# output:
OUT_DIR ?= ../dist

OUT_BPF_DIR := cpu
OUT_BPF := $(OUT_BPF_DIR)/cpu.bpf.o
BPF_BUNDLE := $(OUT_DIR)/parca-agent.bpf.tar.gz

# input:
BPF_HEADERS := ../3rdparty/include
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/$(ARCH)/usr/include
LIBBPF_OBJ := $(OUT_DIR)/libbpf/$(ARCH)/libbpf.a

VMLINUX := cpu/vmlinux.h
BPF_SRC := cpu/cpu.bpf.c

# tasks:
.PHONY: clang
clang: $(OUT_BPF)

bpf_bundle_dir := $(OUT_DIR)/parca-agent.bpf
$(BPF_BUNDLE): $(BPF_SRC) $(LIBBPF_HEADERS)/bpf $(BPF_HEADERS)
	mkdir -p $(bpf_bundle_dir)
	cp $$(find $^ -type f) $(bpf_bundle_dir)

$(OUT_BPF): $(BPF_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(BPF_HEADERS) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(CMD_CC) -S \
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

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
