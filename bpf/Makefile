.PHONY: setup
setup:
	@# Ensure toolchain is installed
	@# https://github.com/rust-lang/rustup/issues/2686
	rustup show active-toolchain 
	cargo install bpf-linker
	rustup component add rust-src

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
