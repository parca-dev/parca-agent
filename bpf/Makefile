.PHONY: build
build: clang

.PHONY: format
format: c/fmt

.PHONY: format-check
format-check:

# environment:
OUT_DIR ?= ../dist
BPF_SRC_DIR := .

ARCH_UNAME := $(shell uname -m)
ifeq ($(ARCH_UNAME),x86_64)
   ARCH = amd64
   LINUX_ARCH = x86
endif
ifeq ($(ARCH_UNAME),aarch64)
   ARCH = arm64
   LINUX_ARCH = arm64
endif

# tools:
CLANG ?= clang
CMD_LLC ?= llc
CMD_CC ?= $(CLANG)

# input:
LIBBPF_HEADERS := $(OUT_DIR)/libbpf/$(ARCH)/usr/include

BPF_CUSTOM_HEADERS := $(BPF_SRC_DIR)/profiler/hash.h
BPF_SRC := $(wildcard $(BPF_SRC_DIR)/**/*.bpf.c)

# output:
BPF_OBJECTS	:= $(patsubst %.c,$(OUT_DIR)/%.o,$(BPF_SRC))
BPF_BUNDLE := $(OUT_DIR)/parca-agent.bpf.tar.gz

# tasks:
.PHONY: clang
clang: $(BPF_OBJECTS)

.PHONY: clean
clean:
	rm -f $(BPF_OBJECTS)
	-rm -rf target/

.PHONY: c/fmt
c/fmt:
	clang-format -i --style=file $(BPF_SRC) $(BPF_HEADERS)

bpf_bundle_dir := $(OUT_DIR)/parca-agent.bpf
$(BPF_BUNDLE): $(BPF_SRC_DIR) $(LIBBPF_HEADERS)/bpf $(BPF_HEADERS)
	mkdir -p $(bpf_bundle_dir)
	cp $$(find $^ -type f) $(bpf_bundle_dir)

# TODO(kakkoyun): Remove!
print:
	@echo $(BPF_SRC_DIR)
	@echo $(OUT_DIR)
	@echo $(BPF_SRC)
	@echo $(BPF_OBJECTS)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(BPF_OBJECTS): $(BPF_SRC) $(LIBBPF_HEADERS) $(LIBBPF_OBJ) $(BPF_HEADERS) $(BPF_CUSTOM_HEADERS) | $(OUT_DIR)
	mkdir -p $(dir $@)
	$(CMD_CC) -S \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-I $(LIBBPF_HEADERS) \
		-I $(BPF_HEADERS) \
		-I $(BPF_CUSTOM_HEADERS) \
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
