.PHONY: setup
setup:
	rustup component add rust-src
	cargo install bpf-linker

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
