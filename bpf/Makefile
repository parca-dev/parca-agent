.PHONY: build
build: clang

.PHONY: clean
clean:
	rm -f $(OUT_BPF)
	-rm -rf target/

.PHONY: format
format: c/fmt

.PHONY: c/fmt
c/fmt:
	clang-format -i --style=file $(BPF_SRC) $(BPF_HEADERS)

.PHONY: format-check
format-check:

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

# TODO(kakkoyun): Generalize for the programs other than profilers.
OUT_BPF_DIR := $(OUT_DIR)/profiler
OUT_BPF := $(OUT_BPF_DIR)/cpu.bpf.o
BPF_BUNDLE := $(OUT_DIR)/parca-agent.bpf.tar.gz

# input:
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/$(ARCH)/usr/include

BPF_SRC_DIR := profiler
BPF_SRC := $(BPF_SRC_DIR)/cpu.bpf.c
BPF_HEADERS := $(BPF_SRC_DIR)/hash.h

# tasks:
.PHONY: clang
clang: $(OUT_BPF)

bpf_bundle_dir := $(OUT_DIR)/parca-agent.bpf
$(BPF_BUNDLE): $(BPF_SRC) $(LIBBPF_HEADERS)/bpf $(BPF_HEADERS)
	mkdir -p $(bpf_bundle_dir)
	cp $$(find $^ -type f) $(bpf_bundle_dir)

$(OUT_BPF): $(BPF_SRC) $(LIBBPF_HEADERS) $(BPF_HEADERS) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(CMD_CC) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-I $(LIBBPF_HEADERS) \
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
