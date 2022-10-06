# renovate: datasource=github-releases depName=aya-rs/bpf-linker
BPF_LINKER_VERSION := v0.9.5

LLVM_SYS_140_PREFIX ?= /usr/lib/llvm-14

.PHONY: setup
setup:
	rustup show
	# we need to do this as we're using an external LLVM. See: https://github.com/aya-rs/bpf-linker#using-external-llvm
	# TODO(vadorovsky): Remove the LLVM_SYS_140_PREFIX variable once
	# https://gitlab.com/taricorp/llvm-sys.rs/-/merge_requests/22 is merged.
	# FIXME: Fix Rust warnings upstream and remove empty RUSTFLAGS environment variable
	LLVM_SYS_140_PREFIX=$(LLVM_SYS_140_PREFIX) RUSTFLAGS= cargo install --locked --git https://github.com/aya-rs/bpf-linker --tag $(BPF_LINKER_VERSION) --no-default-features --features system-llvm -- bpf-linker

.PHONY: build
build:
	cargo xtask build-ebpf --release

.PHONY: clean
clean:
	cargo clean

.PHONY: format
format:
	cargo fmt

.PHONY: format-check
format-check:
	cargo fmt --check

.PHONY: lint
lint:
	cargo clippy
	cargo doc

lint-fix:
	cargo clippy --fix
