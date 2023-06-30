.PHONY: build
build: clang

.PHONY: clean
clean:
	rm -rf $(OUT_BPF_BASE_DIR)
	-rm -rf target/

.PHONY: format
format: c/fmt

.PHONY: c/fmt
c/fmt:
	clang-format -i --style=file $(BPF_SRC) $(BPF_HEADERS)

.PHONY: format-check
format-check:

# environment:
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
SHORT_ARCH ?= $(subst amd64,x86,$(ARCH))

# tools:
CLANG ?= clang
CMD_LLC ?= llc
CMD_CC ?= $(CLANG)

# output:
OUT_DIR ?= ../dist

OUT_BPF_BASE_DIR := out
OUT_BPF_DIR := $(OUT_BPF_BASE_DIR)/$(ARCH)
OUT_BPF := $(OUT_BPF_DIR)/cpu.bpf.o
BPF_BUNDLE := $(OUT_DIR)/parca-agent.bpf.tar.gz

# input:
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/$(ARCH)/usr/include

VMLINUX_INCLUDE_PATH := $(SHORT_ARCH)
BPF_SRC := cpu/cpu.bpf.c
BPF_INCLUDES := cpu/

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
		-D__TARGET_ARCH_$(SHORT_ARCH) \
		-I $(VMLINUX_INCLUDE_PATH) \
		-I $(LIBBPF_HEADERS) \
		-I $(BPF_INCLUDES) \
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
