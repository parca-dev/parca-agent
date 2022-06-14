.PHONY: setup
setup:
	rustup show
	# we need to do this as we're using an external LLVM. See: https://github.com/aya-rs/bpf-linker#using-external-llvm
	# TODO(vadorovsky): Remove the LLVM_SYS_140_PREFIX variable once
	# https://gitlab.com/taricorp/llvm-sys.rs/-/merge_requests/22 is merged.
	LLVM_SYS_140_PREFIX=/usr/lib/llvm-14 cargo install --git https://github.com/aya-rs/bpf-linker --tag v0.9.4 --no-default-features --features system-llvm -- bpf-linker

.PHONY: build
build:
	cargo xtask build-ebpf --release

.PHONY: clean
clean:
	cargo clean

.PHONY: format
format:
	rustfmt cpu-profiler/**/*.rs

.PHONY: lint
lint:
	cargo clippy
