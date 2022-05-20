.PHONY: setup
setup:
	rustup install nightly
	cargo install bpf-linker
	rustup component add rust-src --toolchain nightly

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