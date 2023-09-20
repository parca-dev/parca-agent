# tools:
CLANG ?= clang
CMD_CLANG_FORMAT ?= clang-format
CMD_LLC ?= llc
CMD_CC ?= $(CLANG)

# environment:
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
SHORT_ARCH ?= $(subst amd64,x86,$(ARCH))

# output:
OUT_DIR ?= ../dist

OUT_BPF_BASE_DIR := out
OUT_BPF_DIR := $(OUT_BPF_BASE_DIR)/$(ARCH)
OUT_BPF := $(OUT_BPF_DIR)/cpu.bpf.o
# TODO(kakkoyun): DRY.
OUT_RBPERF := $(OUT_BPF_DIR)/rbperf.bpf.o
OUT_PYPERF := $(OUT_BPF_DIR)/pyperf.bpf.o
OUT_PID_NAMESPACE_DETECTOR := $(OUT_BPF_DIR)/pid_namespace.bpf.o
BPF_BUNDLE := $(OUT_DIR)/parca-agent.bpf.tar.gz

# input:
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/$(ARCH)/usr/include

VMLINUX_INCLUDE_PATH := $(SHORT_ARCH)
# TODO(kakkoyun): DRY.
BPF_SRC := cpu/cpu.bpf.c
RBPERF_SRC := cpu/rbperf.bpf.c
PYPERF_SRC := cpu/pyperf.bpf.c
OUT_PID_NAMESPACE_DETECTOR_SRC := pid_namespace.bpf.c
BPF_INCLUDES := cpu/

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
	$(CMD_CLANG_FORMAT) -i --style=file $(BPF_HEADERS) $(BPF_SRC) $(RBPERF_SRC) $(PYPERF_SRC)

.PHONY: format-check
format-check:

# compilation options:
BPF_CFLAGS = -Wno-address-of-packed-member \
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
		-O2

# tasks:
.PHONY: clang
clang: $(OUT_BPF) $(OUT_RBPERF) $(OUT_PYPERF) $(OUT_PID_NAMESPACE_DETECTOR)

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
		$(BPF_CFLAGS) \
		-emit-llvm -c -g $< -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)

$(OUT_RBPERF): $(RBPERF_SRC) $(LIBBPF_HEADERS) $(BPF_HEADERS) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(CMD_CC) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(SHORT_ARCH) \
		-I $(VMLINUX_INCLUDE_PATH) \
		-I $(LIBBPF_HEADERS) \
		-I $(BPF_INCLUDES) \
		$(BPF_CFLAGS) \
		-emit-llvm -c -g $< -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)

$(OUT_PID_NAMESPACE_DETECTOR): $(OUT_PID_NAMESPACE_DETECTOR_SRC) $(LIBBPF_HEADERS) $(BPF_HEADERS) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(CMD_CC) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(SHORT_ARCH) \
		-I $(VMLINUX_INCLUDE_PATH) \
		-I $(LIBBPF_HEADERS) \
		-I $(BPF_INCLUDES) \
		$(BPF_CFLAGS) \
		-emit-llvm -c -g $< -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)

$(OUT_PYPERF): $(PYPERF_SRC) $(LIBBPF_HEADERS) $(BPF_HEADERS) | $(OUT_DIR)
	mkdir -p $(OUT_BPF_DIR)
	$(CMD_CC) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(SHORT_ARCH) \
		-I $(VMLINUX_INCLUDE_PATH) \
		-I $(LIBBPF_HEADERS) \
		-I $(BPF_INCLUDES) \
		$(BPF_CFLAGS) \
		-O2 -emit-llvm -c -g $< -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)
